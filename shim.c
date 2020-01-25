#ifndef MBEDTLE_SHIM_C
#define MBEDTLE_SHIM_C
#endif

#include "shim.h"

int X_mbedtls_sha1_ret(unsigned char *src, int len, unsigned char *out) {
    int ret = 0;
#ifdef MBEDTLS_MD_C
    MD_HASH("SHA1", src, len, out);
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
    MD_HASH("SHA256", src, len, out);
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
    MD_HASH("SHA512", src, len, out);
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
    MD_HASH("MD5", src, len, out);
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
    MD_HASH("RIPEMD160", src, len, out);
#elif defined(MBEDTLS_RIPEMD160_C)
    ret = mbedtls_ripemd160_ret(src, len, out);
    return ret;
#else
    ret = ERR_FUNCTION_NOT_SUPPORTED;
    return ret;
#endif
}