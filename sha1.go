package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	// EmptySHA1Hash is sha1 hash of empty data
	EmptySHA1Hash = [20]byte{218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9}
)

// Sha1 returns sha1 hash of given data
func Sha1(src []byte) (out [20]byte, err error) {
	if len(src) == 0 {
		out = EmptySHA1Hash
		return
	}
	ret := C.X_mbedtls_sha1_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
