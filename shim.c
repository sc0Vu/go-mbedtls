#ifndef MBEDTLE_SHIM_C
#define MBEDTLE_SHIM_C
#endif

#include "shim.h"

int X_mbedtls_sha1_ret (unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_string("SHA1");
    if (md_info == NULL) {
        ret = ERR_FUNCTION_NOT_SUPPORTED;
        goto exit;
    }
    if ((ret = mbedtls_md(md_info, src, len, out)) != 0) {
        goto exit;
    }
exit:
    return ret;
#elif defined(MBEDTLS_SHA1_C)
    ret = mbedtls_sha1_ret(src, len, out);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

int X_mbedtls_sha256_ret (unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_string("SHA256");
    if (md_info == NULL) {
        ret = ERR_FUNCTION_NOT_SUPPORTED;
        goto exit;
    }
    if ((ret = mbedtls_md(md_info, src, len, out)) != 0) {
        goto exit;
    }
exit:
    return ret;
#elif defined(MBEDTLS_SHA256_C)
    int is224 = 0;
    ret = mbedtls_sha256_ret(src, len, out, is224);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

int X_mbedtls_sha512_ret (unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_string("SHA512");
    if (md_info == NULL) {
        ret = ERR_FUNCTION_NOT_SUPPORTED;
        goto exit;
    }
    if ((ret = mbedtls_md(md_info, src, len, out)) != 0) {
        goto exit;
    }
exit:
    return ret;
#elif defined(MBEDTLS_SHA512_C)
    int is384 = 1;
    ret = mbedtls_sha512_ret(src, len, out, is384);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}

int X_mbedtls_md5_ret (unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_string("MD5");
    if (md_info == NULL) {
        ret = ERR_FUNCTION_NOT_SUPPORTED;
        goto exit;
    }
    if ((ret = mbedtls_md(md_info, src, len, out)) != 0) {
        goto exit;
    }
exit:
    return ret;
#elif defined(MBEDTLS_MD5_C)
    ret = mbedtls_md5_ret(src, len, out);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}