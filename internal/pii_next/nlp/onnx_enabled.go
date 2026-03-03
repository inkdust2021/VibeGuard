//go:build onnx && cgo

package nlp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/inkdust2021/vibeguard/internal/pii_next/nlp/onnxruntime"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

func OnnxAvailable() bool { return onnxruntime.Available() }

type onnxModelConfig struct {
	Type        string  `json:"type"`
	Model       string  `json:"model"`
	Vocab       string  `json:"vocab"`
	Labels      string  `json:"labels"`
	DoLowerCase bool    `json:"do_lower_case"`
	MaxLength   int     `json:"max_length"`
	MinScore    float64 `json:"min_score"`
	Inputs      struct {
		InputIDs      string `json:"input_ids"`
		AttentionMask string `json:"attention_mask"`
		TokenTypeIDs  string `json:"token_type_ids"`
	} `json:"inputs"`
	Outputs struct {
		Logits string `json:"logits"`
	} `json:"outputs"`
}

type onnxNER struct {
	env    *onnxruntime.Env
	sess   *onnxruntime.Session
	tok    *wordpieceTokenizer
	labels []string

	inputNames []string
	outputName string
	maxLen     int
	minScore   float64
}

func loadOnnxNER(modelPath string, minScore float64) (*onnxNER, error) {
	dir, err := resolveModelDir(modelPath)
	if err != nil {
		return nil, err
	}

	cfg := onnxModelConfig{
		Type:        "bert-token-classifier",
		Model:       "model.onnx",
		Vocab:       "vocab.txt",
		Labels:      "labels.txt",
		DoLowerCase: false,
		MaxLength:   128,
		MinScore:    0,
	}
	cfgPath := filepath.Join(dir, "vibeguard_ner.json")
	if b, err := os.ReadFile(cfgPath); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}

	if cfg.MaxLength <= 16 {
		cfg.MaxLength = 128
	}
	if cfg.Inputs.InputIDs == "" {
		cfg.Inputs.InputIDs = "input_ids"
	}
	if cfg.Inputs.AttentionMask == "" {
		cfg.Inputs.AttentionMask = "attention_mask"
	}
	if cfg.Outputs.Logits == "" {
		cfg.Outputs.Logits = "logits"
	}

	modelFile := filepath.Join(dir, filepath.Clean(cfg.Model))
	vocabFile := filepath.Join(dir, filepath.Clean(cfg.Vocab))
	labelsFile := filepath.Join(dir, filepath.Clean(cfg.Labels))

	vocab, err := loadLinesMap(vocabFile)
	if err != nil {
		return nil, fmt.Errorf("加载 vocab 失败：%w", err)
	}
	labels, err := loadLines(labelsFile)
	if err != nil {
		return nil, fmt.Errorf("加载 labels 失败：%w", err)
	}
	if len(labels) == 0 {
		return nil, fmt.Errorf("labels 为空：%s", labelsFile)
	}

	env, err := onnxruntime.NewEnv()
	if err != nil {
		return nil, err
	}
	sess, err := onnxruntime.NewSession(env, modelFile)
	if err != nil {
		_ = env.Close()
		return nil, err
	}

	tok := newWordpieceTokenizer(vocab, cfg.DoLowerCase)
	min := minScore
	if min <= 0 {
		min = cfg.MinScore
	}
	if min <= 0 {
		min = 0.60
	}

	inputNames := []string{cfg.Inputs.InputIDs, cfg.Inputs.AttentionMask}
	if strings.TrimSpace(cfg.Inputs.TokenTypeIDs) != "" {
		inputNames = append(inputNames, cfg.Inputs.TokenTypeIDs)
	}

	m := &onnxNER{
		env:        env,
		sess:       sess,
		tok:        tok,
		labels:     labels,
		inputNames: inputNames,
		outputName: cfg.Outputs.Logits,
		maxLen:     cfg.MaxLength,
		minScore:   min,
	}
	runtime.SetFinalizer(m, func(m *onnxNER) { _ = m.Close() })
	return m, nil
}

func (m *onnxNER) Close() error {
	if m == nil {
		return nil
	}
	if m.sess != nil {
		_ = m.sess.Close()
		m.sess = nil
	}
	if m.env != nil {
		_ = m.env.Close()
		m.env = nil
	}
	return nil
}

type onnxRecognizer struct {
	model *onnxNER

	enabledEntities map[string]struct{}
	priority        int
	mu              sync.Mutex
}

func newOnnxRecognizer(opts Options) (recognizer.Recognizer, error) {
	ent := normalizeEntities(opts.Entities)
	// 仅支持这三类（与 UI 选项保持一致）
	for k := range ent {
		if k != "PERSON" && k != "ORG" && k != "LOCATION" {
			return nil, ErrUnsupportedEntities
		}
	}

	m, err := loadOnnxNER(opts.ModelPath, opts.MinScore)
	if err != nil {
		return nil, err
	}
	r := &onnxRecognizer{
		model:           m,
		enabledEntities: ent,
		priority:        95,
	}
	runtime.SetFinalizer(r, func(r *onnxRecognizer) { _ = r.Close() })
	return r, nil
}

func (r *onnxRecognizer) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.model != nil {
		_ = r.model.Close()
		r.model = nil
	}
	return nil
}

func (r *onnxRecognizer) Name() string { return "nlp-onnx" }

func (r *onnxRecognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil {
		return nil
	}
	if len(input) == 0 || len(input) > 512*1024 {
		return nil
	}

	r.mu.Lock()
	m := r.model
	r.mu.Unlock()
	if m == nil || m.sess == nil || m.tok == nil {
		return nil
	}

	text := string(input)
	pieces := m.tok.Tokenize(text)
	if len(pieces) == 0 {
		return nil
	}

	maxLen := m.maxLen
	if maxLen <= 16 {
		maxLen = 128
	}
	maxContent := maxLen - 2
	if maxContent <= 0 {
		return nil
	}

	stride := 16
	if stride >= maxContent {
		stride = 0
	}

	var all []recognizer.Match
	for start := 0; start < len(pieces); {
		end := start + maxContent
		if end > len(pieces) {
			end = len(pieces)
		}
		seg := pieces[start:end]

		ms := r.runSegment(m, seg, maxLen)
		if len(ms) > 0 {
			all = append(all, ms...)
		}

		if end >= len(pieces) {
			break
		}
		if stride == 0 {
			start = end
		} else {
			start = end - stride
			if start < 0 {
				start = 0
			}
		}
	}

	if len(all) == 0 {
		return nil
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		if all[i].End != all[j].End {
			return all[i].End < all[j].End
		}
		return all[i].Category < all[j].Category
	})
	out := all[:0]
	for i := range all {
		if i > 0 && all[i].Start == all[i-1].Start && all[i].End == all[i-1].End && all[i].Category == all[i-1].Category {
			continue
		}
		out = append(out, all[i])
	}
	return out
}

func (r *onnxRecognizer) runSegment(m *onnxNER, seg []tokenPiece, maxLen int) []recognizer.Match {
	// Build inputs
	inputIDs := make([]int64, 0, maxLen)
	attn := make([]int64, 0, maxLen)
	var typeIDs []int64

	inputIDs = append(inputIDs, int64(m.tok.clsID))
	attn = append(attn, 1)
	for _, p := range seg {
		inputIDs = append(inputIDs, int64(p.id))
		attn = append(attn, 1)
	}
	inputIDs = append(inputIDs, int64(m.tok.sepID))
	attn = append(attn, 1)

	if len(m.inputNames) >= 3 {
		typeIDs = make([]int64, len(inputIDs))
	}

	for len(inputIDs) < maxLen {
		inputIDs = append(inputIDs, int64(m.tok.padID))
		attn = append(attn, 0)
		if typeIDs != nil {
			typeIDs = append(typeIDs, 0)
		}
	}
	if len(inputIDs) > maxLen {
		inputIDs = inputIDs[:maxLen]
		attn = attn[:maxLen]
		if typeIDs != nil {
			typeIDs = typeIDs[:maxLen]
		}
	}

	shape := []int64{1, int64(maxLen)}
	in0, err := onnxruntime.NewTensorInt64(m.sess, shape, inputIDs)
	if err != nil {
		return nil
	}
	defer in0.Close()
	in1, err := onnxruntime.NewTensorInt64(m.sess, shape, attn)
	if err != nil {
		return nil
	}
	defer in1.Close()

	var in2 *onnxruntime.Value
	if typeIDs != nil {
		in2, err = onnxruntime.NewTensorInt64(m.sess, shape, typeIDs)
		if err != nil {
			return nil
		}
		defer in2.Close()
	}

	var inputs []*onnxruntime.Value
	inputs = append(inputs, in0, in1)
	if in2 != nil {
		inputs = append(inputs, in2)
	}

	outs, err := m.sess.Run([]string{m.outputName}, m.inputNames, inputs)
	if err != nil || len(outs) == 0 {
		for _, o := range outs {
			o.Close()
		}
		return nil
	}
	defer outs[0].Close()

	logits, shp, err := onnxruntime.TensorFloat32Data(outs[0])
	if err != nil {
		return nil
	}
	if len(shp) != 3 || shp[0] != 1 || int(shp[1]) != maxLen {
		return nil
	}
	numLabels := int(shp[2])
	if numLabels <= 1 || numLabels > 256 || numLabels != len(m.labels) {
		return nil
	}

	// Decode labels for token positions (skip [CLS]=0 and [SEP]=len(seg)+1)
	var spans []pred

	curCat := ""
	curStart := -1
	curEnd := -1

	for i := 0; i < len(seg); i++ {
		pos := 1 + i
		if pos >= maxLen {
			break
		}
		if attn[pos] == 0 {
			break
		}

		labelID, score := argmaxSoftmax(logits, pos, numLabels)
		if labelID < 0 || labelID >= len(m.labels) || score < m.minScore {
			flushSpan(&spans, &curCat, &curStart, &curEnd)
			continue
		}
		label := m.labels[labelID]
		ent, ok := mapLabelToEntity(label)
		if !ok || !r.entityEnabled(ent) {
			flushSpan(&spans, &curCat, &curStart, &curEnd)
			continue
		}

		p := seg[i]
		if p.start < 0 || p.end < 0 || p.start >= p.end {
			flushSpan(&spans, &curCat, &curStart, &curEnd)
			continue
		}

		if curCat == "" || curCat != ent || !isContinueLabel(label) {
			flushSpan(&spans, &curCat, &curStart, &curEnd)
			curCat = ent
			curStart = p.start
			curEnd = p.end
			continue
		}
		if curStart < 0 {
			curStart = p.start
		}
		if p.start < curStart {
			curStart = p.start
		}
		if p.end > curEnd {
			curEnd = p.end
		}
	}
	flushSpan(&spans, &curCat, &curStart, &curEnd)

	if len(spans) == 0 {
		return nil
	}

	out := make([]recognizer.Match, 0, len(spans))
	for _, s := range spans {
		if s.start < 0 || s.end < 0 || s.start >= s.end {
			continue
		}
		out = append(out, recognizer.Match{
			Start:    s.start,
			End:      s.end,
			Category: s.cat,
			Priority: r.priority,
			Source:   r.Name(),
		})
	}
	return out
}

func (r *onnxRecognizer) entityEnabled(cat string) bool {
	_, ok := r.enabledEntities[cat]
	return ok
}

type pred struct {
	start int
	end   int
	cat   string
}

func flushSpan(out *[]pred, curCat *string, curStart *int, curEnd *int) {
	if curCat == nil || curStart == nil || curEnd == nil {
		return
	}
	if *curCat != "" && *curStart >= 0 && *curEnd > *curStart {
		*out = append(*out, pred{start: *curStart, end: *curEnd, cat: *curCat})
	}
	*curCat = ""
	*curStart = -1
	*curEnd = -1
}

func isContinueLabel(label string) bool {
	// 简化：B- 作为新实体；I- 视为可续接；其他一律不续接。
	ul := strings.ToUpper(strings.TrimSpace(label))
	return strings.HasPrefix(ul, "I-")
}

func mapLabelToEntity(label string) (string, bool) {
	ul := strings.ToUpper(strings.TrimSpace(label))
	if ul == "" || ul == "O" {
		return "", false
	}
	if strings.HasPrefix(ul, "B-") || strings.HasPrefix(ul, "I-") {
		ul = ul[2:]
	}
	switch ul {
	case "PER", "PERSON", "NR":
		return "PERSON", true
	case "ORG", "ORGANIZATION", "NT":
		return "ORG", true
	case "LOC", "LOCATION", "GPE", "NS":
		return "LOCATION", true
	default:
		return "", false
	}
}

func argmaxSoftmax(logits []float32, pos int, numLabels int) (labelID int, score float64) {
	off := pos * numLabels
	if off < 0 || off+numLabels > len(logits) {
		return -1, 0
	}
	maxV := float64(logits[off])
	for i := 1; i < numLabels; i++ {
		v := float64(logits[off+i])
		if v > maxV {
			maxV = v
		}
	}
	var sum float64
	best := 0
	bestV := float64(logits[off])
	for i := 0; i < numLabels; i++ {
		v := float64(logits[off+i])
		if v > bestV {
			bestV = v
			best = i
		}
		sum += math.Exp(v - maxV)
	}
	p := math.Exp(bestV-maxV) / sum
	return best, p
}

type tokenPiece struct {
	id    int
	start int
	end   int
}

type wordpieceTokenizer struct {
	vocab       map[string]int
	doLowerCase bool

	unkID int
	clsID int
	sepID int
	padID int
}

func newWordpieceTokenizer(vocab map[string]int, doLower bool) *wordpieceTokenizer {
	t := &wordpieceTokenizer{
		vocab:       vocab,
		doLowerCase: doLower,
		unkID:       0,
		clsID:       0,
		sepID:       0,
		padID:       0,
	}
	if id, ok := vocab["[UNK]"]; ok {
		t.unkID = id
	}
	if id, ok := vocab["[CLS]"]; ok {
		t.clsID = id
	}
	if id, ok := vocab["[SEP]"]; ok {
		t.sepID = id
	}
	if id, ok := vocab["[PAD]"]; ok {
		t.padID = id
	}
	return t
}

func (t *wordpieceTokenizer) Tokenize(s string) []tokenPiece {
	if t == nil || len(t.vocab) == 0 || s == "" {
		return nil
	}
	var out []tokenPiece
	for _, tok := range basicTokenize(s) {
		pieces := t.wordpiece(tok.text)
		if len(pieces) == 0 {
			continue
		}
		for _, p := range pieces {
			out = append(out, tokenPiece{id: p.id, start: tok.start + p.start, end: tok.start + p.end})
		}
	}
	return out
}

type basicToken struct {
	text  string
	start int
	end   int
}

func basicTokenize(s string) []basicToken {
	var out []basicToken

	start := -1
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if start >= 0 {
				out = append(out, basicToken{text: s[start:i], start: start, end: i})
				start = -1
			}
			i++
			continue
		}

		if unicode.IsSpace(r) {
			if start >= 0 {
				out = append(out, basicToken{text: s[start:i], start: start, end: i})
				start = -1
			}
			i += size
			continue
		}

		if unicode.Is(unicode.Han, r) {
			if start >= 0 {
				out = append(out, basicToken{text: s[start:i], start: start, end: i})
				start = -1
			}
			out = append(out, basicToken{text: s[i : i+size], start: i, end: i + size})
			i += size
			continue
		}

		if isPunct(r) {
			if start >= 0 {
				out = append(out, basicToken{text: s[start:i], start: start, end: i})
				start = -1
			}
			out = append(out, basicToken{text: s[i : i+size], start: i, end: i + size})
			i += size
			continue
		}

		if start < 0 {
			start = i
		}
		i += size
	}
	if start >= 0 {
		out = append(out, basicToken{text: s[start:], start: start, end: len(s)})
	}
	return out
}

func isPunct(r rune) bool {
	if r <= 0x7F {
		switch r {
		case '.', ',', ';', ':', '!', '?', '"', '\'', '(', ')', '[', ']', '{', '}', '<', '>', '/', '\\', '|', '@', '#', '$', '%', '^', '&', '*', '-', '_', '+', '=':
			return true
		default:
			return false
		}
	}
	return unicode.IsPunct(r)
}

type wpPiece struct {
	id    int
	start int
	end   int
}

func (t *wordpieceTokenizer) wordpiece(token string) []wpPiece {
	if token == "" {
		return nil
	}
	if t.doLowerCase {
		token = strings.ToLower(token)
	}

	rs := []rune(token)
	// 粗暴上限，防止极端长 token 卡死
	if len(rs) > 200 {
		return []wpPiece{{id: t.unkID, start: 0, end: len(token)}}
	}

	// 预计算 rune->byte 的边界
	bytePos := make([]int, len(rs)+1)
	bi := 0
	for i, r := range rs {
		bytePos[i] = bi
		bi += utf8.RuneLen(r)
	}
	bytePos[len(rs)] = bi

	var out []wpPiece
	for start := 0; start < len(rs); {
		found := -1
		foundID := -1
		for end := len(rs); end > start; end-- {
			sub := string(rs[start:end])
			key := sub
			if start > 0 {
				key = "##" + sub
			}
			if id, ok := t.vocab[key]; ok {
				found = end
				foundID = id
				break
			}
		}
		if found == -1 {
			return []wpPiece{{id: t.unkID, start: 0, end: len(token)}}
		}
		out = append(out, wpPiece{id: foundID, start: bytePos[start], end: bytePos[found]})
		start = found
	}
	return out
}

func resolveModelDir(modelPath string) (string, error) {
	p := strings.TrimSpace(modelPath)
	if p == "" {
		return "", fmt.Errorf("空的 model_path")
	}
	p = expandHome(p)

	fi, err := os.Stat(p)
	if err == nil && fi.IsDir() {
		return p, nil
	}
	// 若给的是 onnx 文件路径，则使用其所在目录
	if err == nil && !fi.IsDir() {
		return filepath.Dir(p), nil
	}
	// 相对路径：尝试相对 cwd 与可执行文件目录
	if !filepath.IsAbs(p) {
		if fi, err := os.Stat(filepath.Clean(p)); err == nil && fi.IsDir() {
			return filepath.Clean(p), nil
		}
		if exe, err := os.Executable(); err == nil {
			cand := filepath.Join(filepath.Dir(exe), p)
			if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
				return cand, nil
			}
		}
	}
	return "", fmt.Errorf("找不到 model_path：%s", modelPath)
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	// 允许较长行（vocab 里可能有长 token）
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func loadLinesMap(path string) (map[string]int, error) {
	lines, err := loadLines(path)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, len(lines))
	for i, s := range lines {
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = i
	}
	return m, nil
}
