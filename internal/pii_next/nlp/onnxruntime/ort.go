//go:build onnx && cgo

package onnxruntime

/*
#cgo CFLAGS: -I${SRCDIR}/include
// 运行期动态加载 onnxruntime（避免构建期依赖固定安装路径）。
// 说明：
// - macOS/Linux：通过 dlopen + dlsym 找到 OrtGetApiBase
// - Linux 需要链接 libdl
#cgo linux LDFLAGS: -ldl

// NOTE: We intentionally vendor the single C API header (MIT licensed) to avoid relying on
// platform-specific dev packages for headers.
#include "onnxruntime_c_api.h"

#include <dlfcn.h>
#include <stdlib.h>

typedef const OrtApiBase* (*vg_ort_get_api_base_fn)(void);

static void* vg_ort_handle = NULL;
static vg_ort_get_api_base_fn vg_ort_get_api_base = NULL;

static int vg_ort_load_once(void) {
  if (vg_ort_get_api_base != NULL) return 1;

  // 可选：用户通过环境变量指定动态库完整路径。
  const char* env = getenv("VIBEGUARD_ONNXRUNTIME_LIB");
  if (env != NULL && env[0] != 0) {
    vg_ort_handle = dlopen(env, RTLD_NOW | RTLD_LOCAL);
  }

#if defined(__APPLE__)
  if (vg_ort_handle == NULL) vg_ort_handle = dlopen("libonnxruntime.dylib", RTLD_NOW | RTLD_LOCAL);
  if (vg_ort_handle == NULL) vg_ort_handle = dlopen("libonnxruntime.1.dylib", RTLD_NOW | RTLD_LOCAL);
#else
  if (vg_ort_handle == NULL) vg_ort_handle = dlopen("libonnxruntime.so", RTLD_NOW | RTLD_LOCAL);
  if (vg_ort_handle == NULL) vg_ort_handle = dlopen("libonnxruntime.so.1", RTLD_NOW | RTLD_LOCAL);
#endif

  if (vg_ort_handle == NULL) return 0;
  vg_ort_get_api_base = (vg_ort_get_api_base_fn)dlsym(vg_ort_handle, "OrtGetApiBase");
  return vg_ort_get_api_base != NULL;
}

static const OrtApi* vg_ort_api(void) {
  static const OrtApi* api = NULL;
  if (api != NULL) return api;

  if (!vg_ort_load_once()) return NULL;

  const OrtApiBase* base = vg_ort_get_api_base();
  if (base == NULL) return NULL;

  // Prefer the newest version supported by the runtime library. The header's ORT_API_VERSION may be newer
  // than the installed library, so we fall back.
  uint32_t v = ORT_API_VERSION;
  // 避免当头文件版本略新于运行库时，GetApi(高版本) 打印噪声错误（不影响后续回退）。
  // 目前 VibeGuard 仅用到稳定的推理 API（v24 及以下），因此先对探测版本做一个上限。
  if (v > 24) v = 24;
  while (v > 0) {
    const OrtApi* a = base->GetApi(v);
    if (a != NULL) { api = a; return api; }
    v--;
  }
  return NULL;
}

static const char* vg_ort_error_message(OrtStatus* st) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL || st == NULL) return "onnxruntime: missing api/status";
  return api->GetErrorMessage(st);
}

static void vg_ort_release_status(OrtStatus* st) {
  const OrtApi* api = vg_ort_api();
  if (api != NULL && st != NULL) api->ReleaseStatus(st);
}

static OrtStatus* vg_ort_create_env(OrtEnv** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "vibeguard", out);
}

static void vg_ort_release_env(OrtEnv* env) {
  const OrtApi* api = vg_ort_api();
  if (api != NULL && env != NULL) api->ReleaseEnv(env);
}

static OrtStatus* vg_ort_create_session_options(OrtSessionOptions** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->CreateSessionOptions(out);
}

static void vg_ort_release_session_options(OrtSessionOptions* opt) {
  const OrtApi* api = vg_ort_api();
  if (api != NULL && opt != NULL) api->ReleaseSessionOptions(opt);
}

static OrtStatus* vg_ort_create_session(OrtEnv* env, const ORTCHAR_T* model_path, OrtSessionOptions* opt, OrtSession** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->CreateSession(env, model_path, opt, out);
}

static void vg_ort_release_session(OrtSession* s) {
  const OrtApi* api = vg_ort_api();
  if (api != NULL && s != NULL) api->ReleaseSession(s);
}

static OrtStatus* vg_ort_get_default_allocator(OrtAllocator** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->GetAllocatorWithDefaultOptions(out);
}

static OrtStatus* vg_ort_create_tensor_i64(OrtAllocator* alloc, const int64_t* shape, size_t shape_len, OrtValue** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->CreateTensorAsOrtValue(alloc, shape, shape_len, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, out);
}

static OrtStatus* vg_ort_create_tensor_f32(OrtAllocator* alloc, const int64_t* shape, size_t shape_len, OrtValue** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->CreateTensorAsOrtValue(alloc, shape, shape_len, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, out);
}

static OrtStatus* vg_ort_get_tensor_mut_data(OrtValue* v, void** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->GetTensorMutableData(v, out);
}

static OrtStatus* vg_ort_get_tensor_type_shape(const OrtValue* v, OrtTensorTypeAndShapeInfo** out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->GetTensorTypeAndShape(v, out);
}

static void vg_ort_release_tensor_type_shape(OrtTensorTypeAndShapeInfo* info) {
  const OrtApi* api = vg_ort_api();
  if (api != NULL && info != NULL) api->ReleaseTensorTypeAndShapeInfo(info);
}

static OrtStatus* vg_ort_get_dims_count(const OrtTensorTypeAndShapeInfo* info, size_t* out) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->GetDimensionsCount(info, out);
}

static OrtStatus* vg_ort_get_dims(const OrtTensorTypeAndShapeInfo* info, int64_t* dims, size_t dims_len) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->GetDimensions(info, dims, dims_len);
}

static void vg_ort_release_value(OrtValue* v) {
  const OrtApi* api = vg_ort_api();
  if (api != NULL && v != NULL) api->ReleaseValue(v);
}

static OrtStatus* vg_ort_run(OrtSession* s,
  const char* const* input_names, const OrtValue* const* inputs, size_t input_len,
  const char* const* output_names, size_t output_len,
  OrtValue** outputs) {
  const OrtApi* api = vg_ort_api();
  if (api == NULL) return (OrtStatus*)0x1;
  return api->Run(s, NULL, input_names, inputs, input_len, output_names, output_len, outputs);
}

static int vg_ort_api_ok(void) {
  return vg_ort_api() != NULL;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

var ErrORTUnavailable = errors.New("onnxruntime: api unavailable")

func Available() bool {
	return C.vg_ort_api_ok() == 1
}

type Env struct {
	ptr *C.OrtEnv
}

func NewEnv() (*Env, error) {
	if !Available() {
		return nil, ErrORTUnavailable
	}
	var env *C.OrtEnv
	if err := statusErr(C.vg_ort_create_env(&env)); err != nil {
		return nil, err
	}
	e := &Env{ptr: env}
	runtime.SetFinalizer(e, func(e *Env) { _ = e.Close() })
	return e, nil
}

func (e *Env) Close() error {
	if e == nil || e.ptr == nil {
		return nil
	}
	C.vg_ort_release_env(e.ptr)
	e.ptr = nil
	return nil
}

type Session struct {
	ptr   *C.OrtSession
	alloc *C.OrtAllocator // default allocator (do not free)
}

func NewSession(env *Env, modelPath string) (*Session, error) {
	if env == nil || env.ptr == nil {
		return nil, fmt.Errorf("onnxruntime: env is nil")
	}
	if modelPath == "" {
		return nil, fmt.Errorf("onnxruntime: empty model path")
	}

	var alloc *C.OrtAllocator
	if err := statusErr(C.vg_ort_get_default_allocator(&alloc)); err != nil {
		return nil, err
	}

	var opt *C.OrtSessionOptions
	if err := statusErr(C.vg_ort_create_session_options(&opt)); err != nil {
		return nil, err
	}
	defer C.vg_ort_release_session_options(opt)

	cpath := C.CString(modelPath)
	defer C.free(unsafe.Pointer(cpath))

	var sess *C.OrtSession
	if err := statusErr(C.vg_ort_create_session(env.ptr, (*C.ORTCHAR_T)(unsafe.Pointer(cpath)), opt, &sess)); err != nil {
		return nil, err
	}

	s := &Session{ptr: sess, alloc: alloc}
	runtime.SetFinalizer(s, func(s *Session) { _ = s.Close() })
	return s, nil
}

func (s *Session) Close() error {
	if s == nil || s.ptr == nil {
		return nil
	}
	C.vg_ort_release_session(s.ptr)
	s.ptr = nil
	s.alloc = nil
	return nil
}

type Value struct {
	ptr *C.OrtValue
}

func (v *Value) Close() {
	if v == nil || v.ptr == nil {
		return
	}
	C.vg_ort_release_value(v.ptr)
	v.ptr = nil
}

func NewTensorInt64(sess *Session, shape []int64, data []int64) (*Value, error) {
	if sess == nil || sess.alloc == nil {
		return nil, fmt.Errorf("onnxruntime: session allocator is nil")
	}
	if len(shape) == 0 {
		return nil, fmt.Errorf("onnxruntime: empty shape")
	}
	var out *C.OrtValue
	cshape := make([]C.int64_t, len(shape))
	for i, v := range shape {
		cshape[i] = C.int64_t(v)
	}
	if err := statusErr(C.vg_ort_create_tensor_i64(sess.alloc, (*C.int64_t)(unsafe.Pointer(&cshape[0])), C.size_t(len(cshape)), &out)); err != nil {
		return nil, err
	}
	val := &Value{ptr: out}
	// Fill
	if len(data) > 0 {
		var p unsafe.Pointer
		if err := statusErr(C.vg_ort_get_tensor_mut_data(out, (*unsafe.Pointer)(unsafe.Pointer(&p)))); err != nil {
			val.Close()
			return nil, err
		}
		dst := unsafe.Slice((*int64)(p), len(data))
		copy(dst, data)
	}
	return val, nil
}

func TensorFloat32Data(v *Value) (data []float32, shape []int64, err error) {
	if v == nil || v.ptr == nil {
		return nil, nil, fmt.Errorf("onnxruntime: nil value")
	}
	var info *C.OrtTensorTypeAndShapeInfo
	if err := statusErr(C.vg_ort_get_tensor_type_shape(v.ptr, &info)); err != nil {
		return nil, nil, err
	}
	defer C.vg_ort_release_tensor_type_shape(info)

	var nd C.size_t
	if err := statusErr(C.vg_ort_get_dims_count(info, &nd)); err != nil {
		return nil, nil, err
	}
	if nd == 0 || nd > 8 {
		return nil, nil, fmt.Errorf("onnxruntime: unexpected dims count: %d", uint64(nd))
	}
	dims := make([]C.int64_t, int(nd))
	if err := statusErr(C.vg_ort_get_dims(info, (*C.int64_t)(unsafe.Pointer(&dims[0])), nd)); err != nil {
		return nil, nil, err
	}
	shape = make([]int64, int(nd))
	n := int64(1)
	for i := range dims {
		shape[i] = int64(dims[i])
		if shape[i] <= 0 {
			return nil, nil, fmt.Errorf("onnxruntime: invalid dim %d=%d", i, shape[i])
		}
		n *= shape[i]
		if n > 100_000_000 {
			return nil, nil, fmt.Errorf("onnxruntime: tensor too large: %d", n)
		}
	}

	var p unsafe.Pointer
	if err := statusErr(C.vg_ort_get_tensor_mut_data(v.ptr, (*unsafe.Pointer)(unsafe.Pointer(&p)))); err != nil {
		return nil, nil, err
	}
	src := unsafe.Slice((*float32)(p), int(n))
	data = make([]float32, int(n))
	copy(data, src)
	return data, shape, nil
}

func (s *Session) Run(outputNames []string, inputNames []string, inputs []*Value) ([]*Value, error) {
	if s == nil || s.ptr == nil {
		return nil, fmt.Errorf("onnxruntime: nil session")
	}
	if len(outputNames) == 0 || len(inputNames) == 0 {
		return nil, fmt.Errorf("onnxruntime: empty names")
	}
	if len(inputNames) != len(inputs) {
		return nil, fmt.Errorf("onnxruntime: input names/values length mismatch")
	}

	cInNames := make([]*C.char, len(inputNames))
	cInVals := make([]*C.OrtValue, len(inputs))
	for i := range inputNames {
		cInNames[i] = C.CString(inputNames[i])
		defer C.free(unsafe.Pointer(cInNames[i]))
		if inputs[i] == nil || inputs[i].ptr == nil {
			return nil, fmt.Errorf("onnxruntime: nil input %d", i)
		}
		cInVals[i] = inputs[i].ptr
	}

	cOutNames := make([]*C.char, len(outputNames))
	for i := range outputNames {
		cOutNames[i] = C.CString(outputNames[i])
		defer C.free(unsafe.Pointer(cOutNames[i]))
	}
	cOutVals := make([]*C.OrtValue, len(outputNames))

	if err := statusErr(C.vg_ort_run(s.ptr,
		(**C.char)(unsafe.Pointer(&cInNames[0])), (**C.OrtValue)(unsafe.Pointer(&cInVals[0])), C.size_t(len(cInVals)),
		(**C.char)(unsafe.Pointer(&cOutNames[0])), C.size_t(len(cOutNames)),
		(**C.OrtValue)(unsafe.Pointer(&cOutVals[0])))); err != nil {
		return nil, err
	}

	out := make([]*Value, 0, len(cOutVals))
	for i := range cOutVals {
		out = append(out, &Value{ptr: cOutVals[i]})
	}
	return out, nil
}

func statusErr(st *C.OrtStatus) error {
	if st == nil {
		return nil
	}
	msg := C.vg_ort_error_message(st)
	err := fmt.Errorf("onnxruntime: %s", C.GoString(msg))
	C.vg_ort_release_status(st)
	return err
}
