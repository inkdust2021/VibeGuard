package recognizer

// Match 表示一次命中（使用 byte 偏移，左闭右开）。
//
// Priority 越大越优先保留：当多个规则发生重叠时，管线会采用“高优先级优先”的策略，
// 直接丢弃低优先级命中（而不是把大命中拆成碎片替换），避免出现误替换非敏感片段。
type Match struct {
	Start    int
	End      int
	Category string
	Priority int
	Source   string
}

// Recognizer 识别输入中的敏感信息片段。
// 返回的 Match 必须满足：
// - 0 <= Start < End <= len(input)
// - Start/End 为 byte 偏移（不要使用 rune 下标）
type Recognizer interface {
	Name() string
	Recognize(input []byte) []Match
}
