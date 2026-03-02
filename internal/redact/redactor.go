package redact

// Redactor 是脱敏引擎的最小接口（用于 proxy 在不同实现之间切换）。
//
// 约定：实现必须把命中的 Original/Placeholder 填入 matches，以便审计与后续还原使用。
type Redactor interface {
	RedactWithMatches(input []byte) (out []byte, matches []Match)
}
