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
	ctx      *C.mbedtls_md_context_t
	mdInfo   *C.mbedtls_md_info_t
	mdType   C.mbedtls_md_type_t
	mdLength int
}

func NewMessageDigestByType(digest int) (md *MessageDigest) {
	switch digest {
	case MESSAGE_DIGEST_MD5:
		md = &MessageDigest{
			ctx:      nil,
			mdType:   C.MBEDTLS_MD_MD5,
			mdLength: 16,
		}
		break
	case MESSAGE_DIGEST_SHA1:
		md = &MessageDigest{
			ctx:      nil,
			mdType:   C.MBEDTLS_MD_SHA1,
			mdLength: 20,
		}
		break
	case MESSAGE_DIGEST_SHA256:
		md = &MessageDigest{
			ctx:      nil,
			mdType:   C.MBEDTLS_MD_SHA256,
			mdLength: 32,
		}
		break
	case MESSAGE_DIGEST_SHA512:
		md = &MessageDigest{
			ctx:      nil,
			mdType:   C.MBEDTLS_MD_SHA512,
			mdLength: 64,
		}
		break
	case MESSAGE_DIGEST_RIPEMD160:
		md = &MessageDigest{
			ctx:      nil,
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

func NewMessageDigestWithContext(messageDigestType int) (md *MessageDigest, err error) {
	md = NewMessageDigestByType(messageDigestType)
	if md == nil {
		err = ErrHashAlgorithmNotSupported
		return
	}
	ctx := C.X_mbedtls_md_ctx_from_type(md.mdType)
	if ctx == nil {
		err = ErrHashAlgorithmNotSupported
		return
	}
	if ret := C.mbedtls_md_setup(ctx, md.mdInfo, 0); ret != 0 {
		err = ErrHashAlgorithmNotSupported
		return
	}
	if ret := C.mbedtls_md_starts(ctx); ret != 0 {
		err = ErrHashAlgorithmNotSupported
		return
	}
	md.ctx = ctx
	runtime.SetFinalizer(md, func(md *MessageDigest) {
		md.Close()
	})
	return
}

// func NewSha1() (sha1 *SHA1, err error) {
// 	md := getMessageDigestByType(MESSAGE_DIGEST_SHA1)
// 	if md == nil {
// 		err = ErrHashAlgorithmNotSupported
// 		return
// 	}
// 	ctx := C.X_mbedtls_md_ctx_from_type(md.mdType)
// 	if ctx == nil {
// 		err = ErrHashAlgorithmNotSupported
// 		return
// 	}
// 	if ret := C.mbedtls_md_setup(ctx, md.mdInfo, 0); ret != 0 {
// 		err = ErrHashAlgorithmNotSupported
// 		return
// 	}
// 	if ret := C.mbedtls_md_starts(ctx); ret != 0 {
// 		err = ErrHashAlgorithmNotSupported
// 		return
// 	}
// 	sha1 = &SHA1{
// 		ctx: ctx,
// 		md:  md,
// 	}
// 	runtime.SetFinalizer(sha1, func(sha1 *SHA1) {
// 		sha1.Close()
// 	})
// 	return
// }

func (md *MessageDigest) Write(src []byte) (err error) {
	if len(src) == 0 {
		return
	}
	if md.ctx == nil {
		return
	}
	if ret := C.mbedtls_md_update(md.ctx, (*C.uchar)(unsafe.Pointer(&src[0])), C.size_t(len(src))); ret != 0 {
		err = GetMessageDigestErrorByErrorCode(int(ret))
		return
	}
	return
}

func (md *MessageDigest) Finish() (out []byte, err error) {
	if md.ctx == nil {
		return
	}
	out = make([]byte, md.mdLength)
	if ret := C.mbedtls_md_finish(md.ctx, (*C.uchar)(unsafe.Pointer(&out[0]))); ret != 0 {
		err = GetMessageDigestErrorByErrorCode(int(ret))
		return
	}
	return
}

func (md *MessageDigest) Close() {
	C.X_mbedtls_md_free(md.ctx)
}
