package mbedtls

// #include "shim.h"
import "C"

import (
	"unsafe"
)

var (
	EMPTY_MD5_HASH = [16]byte{212, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126}
)

// MD5 returns md5 hash
func MD5(src []byte) (out [16]byte, err error) {
	if len(src) == 0 {
		out = EMPTY_MD5_HASH
		return
	}
	ret := C.X_mbedtls_md5_ret((*C.uchar)(unsafe.Pointer(&src[0])), C.int(len(src)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		err = GetMessageDigestErrorByErrorCode((int)(ret))
		return
	}
	return
}
