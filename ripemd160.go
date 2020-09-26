package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	// EmptyRIPEMD160Hash is ripemd160 hash of empty data
	EmptyRIPEMD160Hash = [20]byte{156, 17, 133, 165, 197, 233, 252, 84, 97, 40, 8, 151, 126, 232, 245, 72, 178, 37, 141, 49}
)

// Ripemd160 returns ripemd160 hash of given data
// Note: RIPEMD-160 is a legacy hash and should not be used for new applications. Also, this package does not and will not provide an optimized implementation. Instead, use a modern hash like SHA-256.
func Ripemd160(src []byte) (out [20]byte, err error) {
	if len(src) == 0 {
		out = EmptyRIPEMD160Hash
		return
	}
	ret := C.X_mbedtls_ripemd160_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
