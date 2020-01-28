#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#endif

#if defined(MBEDTLS_MD_C)
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"

#define MD_HASH_FROM_HASH_NAME(HASH_NAME, SRC, LEN, OUT) \
    const mbedtls_md_info_t *md_info; \
    md_info = mbedtls_md_info_from_string(HASH_NAME); \
    if (md_info == NULL) { \
        ret = ERR_FUNCTION_NOT_SUPPORTED; \
        return ret; \
    } \
    if ((ret = mbedtls_md(md_info, SRC, LEN, OUT)) != 0) { \
        return ret; \
    } \
    return ret;

#define MD_HASH_FROM_HASH_TYPE(HASH_TYPE, SRC, LEN, OUT) \
    const mbedtls_md_info_t *md_info; \
    md_info = mbedtls_md_info_from_type(HASH_TYPE); \
    if (md_info == NULL) { \
        ret = ERR_FUNCTION_NOT_SUPPORTED; \
        return ret; \
    } \
    if ((ret = mbedtls_md(md_info, SRC, LEN, OUT)) != 0) { \
        return ret; \
    } \
    return ret;

#else

#if defined(MBEDTLS_SHA1_C)
#include "mbedtls/sha1.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

#if defined(MBEDTLS_MD5_C)
#include "mbedtls/md5.h"
#endif

#if defined(MBEDTLS_RIPEMD160_C)
#include "mbedtls/ripemd160.h"
#endif
#endif

#include "stdio.h"
#include "stdlib.h"

#define ERR_FUNCTION_NOT_SUPPORTED -0x1111

int X_mbedtls_sha1_ret(unsigned char *src, int len, unsigned char *out);
int X_mbedtls_sha256_ret(unsigned char *src, int len, unsigned char *out);
int X_mbedtls_sha512_ret(unsigned char *src, int len, unsigned char *out);
int X_mbedtls_md5_ret(unsigned char *src, int len, unsigned char *out);
int X_mbedtls_ripemd160_ret(unsigned char *src, int len, unsigned char *out);
mbedtls_md_context_t *X_mbedtls_md_ctx_from_type(const unsigned char *key, size_t keylen, mbedtls_md_type_t md_type);
void X_mbedtls_md_free(mbedtls_md_context_t *ctx);