package mbedtls

// #include "shim.h"
import "C"

import (
	"runtime"
	"unsafe"
)

const (
	MESSAGE_DIGEST_MD5 = iota
	MESSAGE_DIGEST_SHA1
	MESSAGE_DIGEST_SHA256
	MESSAGE_DIGEST_SHA512
	MESSAGE_DIGEST_RIPEMD160
)

type MessageDigest struct {
	mdInfo   *C.mbedtls_md_info_t
	mdType   C.mbedtls_md_type_t
	mdLength int
}

type HMAC struct {
	ctx *C.mbedtls_md_context_t
	md  *MessageDigest
}

func getMessageDigestByType(digest int) (md *MessageDigest) {
	switch digest {
	case MESSAGE_DIGEST_MD5:
		md = &MessageDigest{
			mdType:   C.MBEDTLS_MD_MD5,
			mdLength: 16,
		}
		break
	case MESSAGE_DIGEST_SHA1:
		md = &MessageDigest{
			mdType:   C.MBEDTLS_MD_SHA1,
			mdLength: 20,
		}
		break
	case MESSAGE_DIGEST_SHA256:
		md = &MessageDigest{
			mdType:   C.MBEDTLS_MD_SHA256,
			mdLength: 32,
		}
		break
	case MESSAGE_DIGEST_SHA512:
		md = &MessageDigest{
			mdType:   C.MBEDTLS_MD_SHA512,
			mdLength: 64,
		}
		break
	case MESSAGE_DIGEST_RIPEMD160:
		md = &MessageDigest{
			mdType:   C.MBEDTLS_MD_RIPEMD160,
			mdLength: 20,
		}
		break
	default:
		break
	}
	if md != nil {
		md.mdInfo = C.mbedtls_md_info_from_type(md.mdType)
	}
	return
}

func NewHMAC(privateKey []byte, messageDigestType int) (hmac *HMAC, err error) {
	md := getMessageDigestByType(messageDigestType)
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
