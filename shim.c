#ifndef MBEDTLE_SHIM_C
#define MBEDTLE_SHIM_C
#endif

#include "shim.h"

int X_mbedtls_sha1_ret(unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    MD_HASH_FROM_HASH_TYPE(MBEDTLS_MD_SHA1, src, len, out);
#elif defined(MBEDTLS_SHA1_C)
    ret = mbedtls_sha1_ret(src, len, out);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

int X_mbedtls_sha256_ret(unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    MD_HASH_FROM_HASH_TYPE(MBEDTLS_MD_SHA256, src, len, out);
#elif defined(MBEDTLS_SHA256_C)
    int is224 = 0;
    ret = mbedtls_sha256_ret(src, len, out, is224);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

int X_mbedtls_sha512_ret(unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    MD_HASH_FROM_HASH_TYPE(MBEDTLS_MD_SHA512, src, len, out);
#elif defined(MBEDTLS_SHA512_C)
    int is384 = 1;
    ret = mbedtls_sha512_ret(src, len, out, is384);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

int X_mbedtls_md5_ret(unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    MD_HASH_FROM_HASH_TYPE(MBEDTLS_MD_MD5, src, len, out);
#elif defined(MBEDTLS_MD5_C)
    ret = mbedtls_md5_ret(src, len, out);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

int X_mbedtls_ripemd160_ret(unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    MD_HASH_FROM_HASH_TYPE(MBEDTLS_MD_RIPEMD160, src, len, out);
#elif defined(MBEDTLS_RIPEMD160_C)
    ret = mbedtls_ripemd160_ret(src, len, out);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

mbedtls_md_context_t *X_mbedtls_md_ctx_from_type(mbedtls_md_type_t md_type)
{
    int ret = 0;
#ifdef MBEDTLS_MD_C
    mbedtls_md_context_t *ctx;
    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) {
        return NULL;
    }
    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }
    mbedtls_md_init(ctx);
    if ((ret = mbedtls_md_setup(ctx, md_info, 1)) != 0) {
        // do we need to call free?
        // free(ctx);
        mbedtls_md_free(ctx);
        return NULL;
    }
    return ctx;
#else
    return NULL;
#endif
}

void X_mbedtls_md_free(mbedtls_md_context_t *ctx) {
#ifdef MBEDTLS_MD_C
    // do we need to call free?
    // free(ctx);
    mbedtls_md_free(ctx);
#endif
}