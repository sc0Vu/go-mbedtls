package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	EMPTY_SHA1_HASH = [20]byte{218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9}
)

// Sha1 returns sha1 hash
func Sha1(src []byte) (out [20]byte, err error) {
	if len(src) == 0 {
		out = EMPTY_SHA1_HASH
		return
	}
	ret := C.X_mbedtls_sha1_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
