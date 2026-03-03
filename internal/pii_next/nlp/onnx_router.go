//go:build onnx && cgo

package nlp

import (
	"runtime"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type onnxRouterHandle struct {
	lang     string
	path     string
	rec      *onnxRecognizer
	useStamp uint64
	mu       sync.Mutex
}

func (h *onnxRouterHandle) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rec != nil {
		_ = h.rec.Close()
		h.rec = nil
	}
}

type onnxRouterRecognizer struct {
	enabledEntities map[string]struct{}
	priority        int
	minScore        float64
	maxLoaded       int

	paths map[string]string // lang -> model path

	mu        sync.Mutex
	loaded    map[string]*onnxRouterHandle
	useSerial uint64
}

func newOnnxRouterRecognizer(opts Options) (recognizer.Recognizer, error) {
	ent := normalizeEntities(opts.Entities)
	for k := range ent {
		if k != "PERSON" && k != "ORG" && k != "LOCATION" {
			return nil, ErrUnsupportedEntities
		}
	}

	maxLoaded := opts.MaxLoadedModels
	if maxLoaded <= 0 {
		maxLoaded = 1
	}
	if maxLoaded > 2 {
		maxLoaded = 2
	}

	r := &onnxRouterRecognizer{
		enabledEntities: ent,
		priority:        95,
		minScore:        opts.MinScore,
		maxLoaded:       maxLoaded,
		paths: map[string]string{
			"en": strings.TrimSpace(opts.ModelPathEN),
			"zh": strings.TrimSpace(opts.ModelPathZH),
		},
		loaded: make(map[string]*onnxRouterHandle),
	}
	runtime.SetFinalizer(r, func(r *onnxRouterRecognizer) { _ = r.Close() })
	return r, nil
}

func (r *onnxRouterRecognizer) Name() string { return "nlp-onnx-router" }

func (r *onnxRouterRecognizer) Close() error {
	if r == nil {
		return nil
	}

	var hs []*onnxRouterHandle
	r.mu.Lock()
	for _, h := range r.loaded {
		hs = append(hs, h)
	}
	r.loaded = make(map[string]*onnxRouterHandle)
	r.mu.Unlock()

	for _, h := range hs {
		h.close()
	}
	return nil
}

func (r *onnxRouterRecognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || len(input) == 0 {
		return nil
	}

	langs := r.pickLangs(input)
	if len(langs) == 0 {
		return nil
	}

	var out []recognizer.Match
	for _, lang := range langs {
		h, evict, err := r.getOrLoad(lang)
		if err != nil || h == nil {
			if evict != nil {
				evict.close()
			}
			continue
		}

		h.mu.Lock()
		ms := h.rec.Recognize(input)
		h.mu.Unlock()
		if len(ms) > 0 {
			out = append(out, ms...)
		}

		if evict != nil {
			evict.close()
		}
	}
	return out
}

func (r *onnxRouterRecognizer) pickLangs(input []byte) []string {
	enOK := strings.TrimSpace(r.paths["en"]) != ""
	zhOK := strings.TrimSpace(r.paths["zh"]) != ""
	if !enOK && !zhOK {
		return nil
	}

	hasHan := false
	hasLatin := false
	for i := 0; i < len(input); {
		b := input[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			hasLatin = true
			i++
			continue
		}
		if b < 0x80 {
			i++
			continue
		}
		rn, size := utf8.DecodeRune(input[i:])
		if rn == utf8.RuneError && size == 1 {
			i++
			continue
		}
		if unicode.Is(unicode.Han, rn) {
			hasHan = true
		}
		i += size
	}

	var langs []string
	if hasHan && zhOK {
		langs = append(langs, "zh")
	}
	if hasLatin && enOK {
		langs = append(langs, "en")
	}

	// 混合文本但只配置了一个模型：直接使用可用模型。
	if len(langs) == 0 {
		if enOK {
			return []string{"en"}
		}
		return []string{"zh"}
	}
	return langs
}

func (r *onnxRouterRecognizer) getOrLoad(lang string) (use *onnxRouterHandle, evict *onnxRouterHandle, err error) {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if lang != "en" && lang != "zh" {
		return nil, nil, nil
	}
	path := strings.TrimSpace(r.paths[lang])
	if path == "" {
		return nil, nil, nil
	}

	// Fast path: already loaded.
	r.mu.Lock()
	if h, ok := r.loaded[lang]; ok && h != nil && h.rec != nil {
		r.useSerial++
		h.useStamp = r.useSerial
		r.mu.Unlock()
		return h, nil, nil
	}
	r.mu.Unlock()

	// Load outside lock (可能较慢)。
	m, loadErr := loadOnnxNER(path, r.minScore)
	if loadErr != nil {
		return nil, nil, loadErr
	}
	rec := &onnxRecognizer{
		model:           m,
		enabledEntities: r.enabledEntities,
		priority:        r.priority,
	}
	hNew := &onnxRouterHandle{
		lang: lang,
		path: path,
		rec:  rec,
	}
	runtime.SetFinalizer(hNew, func(h *onnxRouterHandle) { h.close() })

	// Install & maybe evict.
	r.mu.Lock()
	if h, ok := r.loaded[lang]; ok && h != nil && h.rec != nil {
		// Another goroutine already loaded it.
		r.useSerial++
		h.useStamp = r.useSerial
		r.mu.Unlock()
		hNew.close()
		return h, nil, nil
	}
	r.useSerial++
	hNew.useStamp = r.useSerial
	r.loaded[lang] = hNew

	if r.maxLoaded > 0 && len(r.loaded) > r.maxLoaded {
		// Evict least-recently used handle (except the one we just installed).
		var cand *onnxRouterHandle
		for _, h := range r.loaded {
			if h == nil || h == hNew {
				continue
			}
			if cand == nil || h.useStamp < cand.useStamp {
				cand = h
			}
		}
		if cand != nil {
			delete(r.loaded, cand.lang)
			evict = cand
		}
	}
	r.mu.Unlock()

	return hNew, evict, nil
}
