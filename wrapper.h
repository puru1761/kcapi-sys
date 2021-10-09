/*
 * $Id$
 *
 * Copyright 2021 Purushottam A. Kulkarni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and
 * or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE
 *
 */

/*
 * Wrapper for the C API of libkcapi if needed.
 */

#include "kcapi.h"

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