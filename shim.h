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
#endif

#if defined(MBEDTLS_SHA1_C)
#include "mbedtls/sha1.h"
#endif

#include "stdio.h"
#include "stdlib.h"

#define ERR_FUNCTION_NOT_SUPPORTED -0x1111

int X_mbedtls_sha1_ret(unsigned char *src, int len, unsigned char *out);