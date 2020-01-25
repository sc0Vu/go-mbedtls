package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	EMPTY_RIPEMD160_HASH = [20]byte{}
)

// Ripemd160 returns ripemd160 hash
func Ripemd160(src []byte) (out [20]byte, err error) {
	if len(src) == 0 {
		out = EMPTY_RIPEMD160_HASH
		return
	}
	ret := C.X_mbedtls_ripemd160_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
