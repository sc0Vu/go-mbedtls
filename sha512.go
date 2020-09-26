package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	// EmptySHA512Hash is sha512 hash of empty data
	EmptySHA512Hash = [64]byte{207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62}
)

// Sha512 returns sha512 hash of given data
func Sha512(src []byte) (out [64]byte, err error) {
	if len(src) == 0 {
		out = EmptySHA512Hash
		return
	}
	ret := C.X_mbedtls_sha512_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
