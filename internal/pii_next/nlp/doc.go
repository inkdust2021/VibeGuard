// Package nlp 提供“泛化实体识别（NLP）”能力，用于识别人名/组织/位置等实体，
// 并输出与 PII 识别器统一的 Match 列表。
//
// 设计要点：
// - 默认引擎为 heuristic：不依赖外部组件，规则更保守，优先降低误报。
// - 可选引擎为 onnx：需要在构建时启用 `-tags onnx` 且打开 cgo，并提供本地 onnxruntime 动态库与模型文件。
// - ONNX 支持按语言路由（EN/ZH），并支持最多常驻 1~2 个模型以平衡内存与切换速度。
package nlp
