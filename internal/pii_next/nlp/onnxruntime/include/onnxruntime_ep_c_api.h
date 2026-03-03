// 本项目目前不使用 onnxruntime 的 Execution Provider C API。
//
// 上游 onnxruntime 的 onnxruntime_c_api.h 在末尾会 include 本头文件。
// 为了避免构建时依赖系统安装的开发头文件，本项目提供一个“最小占位”版本，
// 只用于满足编译器的 include 需求。
//
// 如果你需要使用 EP 相关的 API（例如 CUDA/TensorRT 等），请用 onnxruntime
// 官方发布包中的同名头文件替换本文件。
#pragma once

