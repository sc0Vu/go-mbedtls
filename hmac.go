package mbedtls

// #include "shim.h"
import "C"

import (
	"runtime"
	"unsafe"
)

type HMAC struct {
	ctx *C.mbedtls_md_context_t
	md  *MessageDigest
}

func NewHMAC(privateKey []byte, messageDigestType int) (hmac *HMAC, err error) {
	md := NewMessageDigestByType(messageDigestType)
	if md == nil {
		err = ErrHashAlgorithmNotSupported
		return
	}
	ctx := C.X_mbedtls_md_ctx_from_type(md.mdType)
	if ctx == nil {
		err = ErrHashAlgorithmNotSupported
		return
	}
	if ret := C.mbedtls_md_hmac_starts(ctx, (*C.uchar)(unsafe.Pointer(&privateKey[0])), C.size_t(len(privateKey))); ret != 0 {
		err = GetMessageDigestErrorByErrorCode(int(ret))
		return
	}
	hmac = &HMAC{
		ctx: ctx,
		md:  md,
	}
	runtime.SetFinalizer(hmac, func(hmac *HMAC) {
		hmac.Close()
	})
	return
}

func (hmac *HMAC) Write(src []byte) (err error) {
	if len(src) == 0 {
		return
	}
	if ret := C.mbedtls_md_hmac_update(hmac.ctx, (*C.uchar)(unsafe.Pointer(&src[0])), C.size_t(len(src))); ret != 0 {
		err = GetMessageDigestErrorByErrorCode(int(ret))
		return
	}
	return
}

func (hmac *HMAC) Finish() (out []byte, err error) {
	out = make([]byte, hmac.md.mdLength)
	if ret := C.mbedtls_md_hmac_finish(hmac.ctx, (*C.uchar)(unsafe.Pointer(&out[0]))); ret != 0 {
		err = GetMessageDigestErrorByErrorCode(int(ret))
		return
	}
	return
}

func (hmac *HMAC) Reset() (err error) {
	if ret := C.mbedtls_md_hmac_reset(hmac.ctx); ret != 0 {
		err = GetMessageDigestErrorByErrorCode(int(ret))
		return
	}
	return
}

func (hmac *HMAC) Close() {
	C.X_mbedtls_md_free(hmac.ctx)
}
