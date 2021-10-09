/*
 * $Id$
 *
 * Wrapper for generating low-level rust bindings for libkcapi
 *
 * Copyright (c) 2021, Purushottam Kulkarni
 * All rights reserved.
 *
 */

#include <kcapi.h>

/*
 * Add all wrappers and redefinitions for libkcapi here
 */
#define BITS_PER_BYTE   8

#define BITSIZE_SHA1           160
#define BITSIZE_SHA224         224
#define BITSIZE_SHA256         256
#define BITSIZE_SHA384         384
#define BITSIZE_SHA512         512

#define SIZE_SHA1       (BITSIZE_SHA1 / BITS_PER_BYTE)
#define SIZE_SHA224     (BITSIZE_SHA224 / BITS_PER_BYTE)
#define SIZE_SHA256     (BITSIZE_SHA256 / BITS_PER_BYTE)
#define SIZE_SHA384     (BITSIZE_SHA384 / BITS_PER_BYTE)
#define SIZE_SHA512     (BITSIZE_SHA512 / BITS_PER_BYTE)

#define AES_BLOCKSIZE_BITS      128
#define AES_BLOCKSIZE    (AES_BLOCKSIZE_BITS / BITS_PER_BYTE)

#define AES128_KEYSIZE_BITS     128
#define AES192_KEYSIZE_BITS     192
#define AES256_KEYSIZE_BITS     256

#define AES128_KEYSIZE    (AES128_KEYSIZE_BITS / BITS_PER_BYTE)
#define AES192_KEYSIZE    (AES192_KEYSIZE_BITS / BITS_PER_BYTE)
#define AES256_KEYSIZE    (AES256_KEYSIZE_BITS / BITS_PER_BYTE)