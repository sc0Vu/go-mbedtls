package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	// EmptyMD5Hash is md5 hash of empty data
	EmptyMD5Hash = [16]byte{212, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126}
)

// MD5 returns md5 hash of given data
func MD5(src []byte) (out [16]byte, err error) {
	if len(src) == 0 {
		out = EmptyMD5Hash
		return
	}
	ret := C.X_mbedtls_md5_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
