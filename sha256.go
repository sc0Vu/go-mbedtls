package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	EMPTY_SHA256_HASH = [32]byte{227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85}
)

// Sha256 returns sha256 hash
func Sha256(src []byte) (out [32]byte, err error) {
	if len(src) == 0 {
		out = EMPTY_SHA256_HASH
		return
	}
	ret := C.X_mbedtls_sha256_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
