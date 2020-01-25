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
        ret = ERROR_FUNCTION_NOT_SUPPORT;
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
    ret = ERROR_FUNCTION_NOT_SUPPORT;
    return ret;
#endif
}