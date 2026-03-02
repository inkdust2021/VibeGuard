package recognizer

// Registry 管理一组 Recognizer。
// 说明：本原型阶段仅做串行执行与结果汇总；并发/超时/缓存等优化可在接入主流程后再做。
type Registry struct {
	recognizers []Recognizer
}

func NewRegistry(recognizers ...Recognizer) *Registry {
	r := &Registry{}
	r.Add(recognizers...)
	return r
}

func (r *Registry) Add(recognizers ...Recognizer) {
	for _, rec := range recognizers {
		if rec == nil {
			continue
		}
		r.recognizers = append(r.recognizers, rec)
	}
}

func (r *Registry) RecognizeAll(input []byte) []Match {
	var out []Match
	for _, rec := range r.recognizers {
		matches := rec.Recognize(input)
		if len(matches) == 0 {
			continue
		}
		out = append(out, matches...)
	}
	return out
}
