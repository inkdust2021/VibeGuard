package redact

import "fmt"

type builtinRule struct {
	pattern  string
	category string
}

var builtinRules = map[string]builtinRule{
	// 说明：
	// - 这里的内置规则用于“开箱即用”的覆盖面提升，避免用户不熟悉正则时无法配置。
	// - 对于需要保留边界字符的场景，使用捕获组让引擎只替换第一个捕获组内容（见 engine.go 的逻辑）。

	"email": {
		pattern:  `(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`,
		category: "EMAIL",
	},
	"china_phone": {
		// 使用捕获组，仅替换手机号本体，保留两侧非数字边界字符。
		pattern:  `(?:^|\D)(1[3-9]\d{9})(?:$|\D)`,
		category: "CHINA_PHONE",
	},
	"china_id": {
		// 使用捕获组，仅替换证件号本体，保留两侧非数字边界字符。
		pattern:  `(?:^|\D)(\d{17}[\dXx])(?:$|\D)`,
		category: "CHINA_ID",
	},
	"uuid": {
		pattern:  `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}`,
		category: "UUID",
	},
	"ipv4": {
		// 不校验每段 0-255 范围；目标是“尽量覆盖 + 低配置成本”。
		pattern:  `(?:\d{1,3}\.){3}\d{1,3}`,
		category: "IPV4",
	},
	"mac": {
		pattern:  `(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}`,
		category: "MAC",
	},
}

// AddBuiltin 向引擎添加内置规则（通常由配置 patterns.builtin 驱动）。
func (e *Engine) AddBuiltin(name string) error {
	rule, ok := builtinRules[name]
	if !ok {
		return fmt.Errorf("unknown builtin rule: %s", name)
	}
	return e.AddRegex(rule.pattern, rule.category)
}
