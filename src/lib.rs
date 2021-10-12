/*
 * $Id$
 *
 * Copyright (c) 2021, Purushottam A. Kulkarni.
 * All rights reserved.
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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/*
 * Sanity Tests for the libkcapi Rust bindings.
 */
#[cfg(test)]

mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(unused_assignments)]
    #![allow(deref_nullptr)]

    use std::convert::TryInto;
    use std::ffi::CString;

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    #[test]
    fn test_md_init() {
        let ret: i32;
        let alg = CString::new("sha1").expect("Failed to convert CString");
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;
            ret = kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), 0);
        }
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_md_digest() {
        let inp = [0x41u8; 16];
        let mut out = [0u8; SIZE_SHA256 as usize];
        let alg = std::ffi::CString::new("sha256").expect("Failed to convert to CString");
        let out_exp = [
            0x99, 0x12, 0x4, 0xfb, 0xa2, 0xb6, 0x21, 0x6d, 0x47, 0x62, 0x82, 0xd3, 0x75, 0xab,
            0x88, 0xd2, 0xe, 0x61, 0x8, 0xd1, 0x9, 0xae, 0xcd, 0xed, 0x97, 0xef, 0x42, 0x4d, 0xdd,
            0x11, 0x47, 0x6,
        ];

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = (kcapi_md_digestsize(handle))
                .try_into()
                .expect("Failed to convert i32 into i64");
            assert_eq!(ret, SIZE_SHA256 as i64);

            ret = kcapi_md_digest(
                handle,
                inp.as_ptr(),
                inp.len() as u64,
                out.as_mut_ptr(),
                out.len() as u64,
            );
            assert_eq!(ret, SIZE_SHA256 as i64);
        }
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_md_keyed_digest() {
        let inp = [0x41u8; 16];
        let mut out = [0u8; SIZE_SHA256 as usize];
        let key = [0u8; 16];
        let alg = std::ffi::CString::new("hmac(sha256)").expect("Failed to convert to CString");
        let out_exp = [
            0x4a, 0x81, 0xd6, 0x13, 0xb0, 0xe, 0x91, 0x9e, 0x8a, 0xd9, 0x63, 0x78, 0x88, 0xe6,
            0xa4, 0xfe, 0x8, 0x22, 0x4a, 0xb6, 0x48, 0x4b, 0xa, 0x37, 0x47, 0xa6, 0xa6, 0x62, 0xb6,
            0xa2, 0x99, 0xd,
        ];

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = (kcapi_md_digestsize(handle))
                .try_into()
                .expect("Failed to convert i32 into i64");
            assert_eq!(ret, SIZE_SHA256 as i64);

            ret = (kcapi_md_setkey(handle, key.as_ptr(), key.len() as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_md_digest(
                handle,
                inp.as_ptr(),
                inp.len() as u64,
                out.as_mut_ptr(),
                out.len() as u64,
            );
            assert_eq!(ret, SIZE_SHA256 as i64);
        }
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_sha1() {
        let inp = [0x41u8; 16];
        let out = [0u8; SIZE_SHA1 as usize];
        let out_exp = [
            0x19, 0xb1, 0x92, 0x8d, 0x58, 0xa2, 0x3, 0xd, 0x8, 0x2, 0x3f, 0x3d, 0x70, 0x54, 0x51,
            0x6d, 0xbc, 0x18, 0x6f, 0x20,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_sha1(
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA1 as i64);
    }

    #[test]
    fn test_sha224() {
        let inp = [0x41u8; 16];
        let out = [0u8; SIZE_SHA224 as usize];
        let out_exp = [
            0xcb, 0xa2, 0x25, 0xbd, 0x2d, 0xed, 0x28, 0xf5, 0xb9, 0xb3, 0xfa, 0xee, 0x8e, 0xca,
            0xed, 0x82, 0xba, 0x8, 0xd2, 0xbb, 0x5a, 0xee, 0x2c, 0x37, 0x40, 0xe7, 0xff, 0x8a,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_sha224(
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA224 as i64);
    }

    #[test]
    fn test_sha256() {
        let inp = [0x41u8; 16];
        let out = [0u8; SIZE_SHA256 as usize];
        let out_exp = [
            0x99, 0x12, 0x4, 0xfb, 0xa2, 0xb6, 0x21, 0x6d, 0x47, 0x62, 0x82, 0xd3, 0x75, 0xab,
            0x88, 0xd2, 0xe, 0x61, 0x8, 0xd1, 0x9, 0xae, 0xcd, 0xed, 0x97, 0xef, 0x42, 0x4d, 0xdd,
            0x11, 0x47, 0x6,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_sha256(
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA256 as i64);
    }

    #[test]
    fn test_sha384() {
        let inp = [0x41u8; 16];
        let out = [0u8; SIZE_SHA384 as usize];
        let out_exp = [
            0x62, 0x5e, 0x92, 0x3, 0x4, 0x7c, 0x52, 0xa1, 0xe2, 0x90, 0x18, 0x9b, 0xd1, 0x5a, 0xbf,
            0x17, 0xe, 0xd8, 0x86, 0xa3, 0x31, 0x90, 0x80, 0x3e, 0x4, 0x40, 0x2f, 0x4d, 0x48, 0xb1,
            0xf, 0xe0, 0x5a, 0xb1, 0x21, 0x97, 0xf9, 0xca, 0xc2, 0x53, 0x74, 0x9a, 0x5f, 0xde, 0x8,
            0x22, 0xc7, 0x34,
        ];
        let ret: i64;
        unsafe {
            ret = kcapi_md_sha384(
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA384 as i64);
    }

    #[test]
    fn test_sha512() {
        let inp = [0x41u8; 16];
        let out = [0u8; SIZE_SHA512 as usize];
        let out_exp = [
            0x67, 0x3a, 0x88, 0x7f, 0xe1, 0x68, 0xc, 0x26, 0xd8, 0x1d, 0x46, 0xd2, 0x76, 0xe6, 0xb,
            0x4d, 0xfd, 0x9c, 0x16, 0x60, 0x34, 0xe7, 0x2f, 0x69, 0xd6, 0x8a, 0x77, 0xf4, 0xb0,
            0xf7, 0x41, 0x21, 0xd4, 0x4b, 0x79, 0x68, 0xde, 0x8f, 0x55, 0xba, 0x26, 0x15, 0xf6,
            0xe7, 0x20, 0xa2, 0xc7, 0x43, 0x99, 0x9c, 0xbc, 0xc0, 0x7a, 0x4, 0x36, 0x6d, 0x9f,
            0x36, 0x46, 0xbc, 0xbc, 0x11, 0x98, 0xce,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_sha512(
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA512 as i64);
    }

    #[test]
    fn test_hmac_sha1() {
        let inp = [0x41u8; 16];
        let key = [0u8; 16];
        let out = [0u8; SIZE_SHA1 as usize];
        let out_exp = [
            0x41, 0x85, 0xf6, 0xa4, 0xc3, 0xab, 0x30, 0xf9, 0xa8, 0x5, 0x96, 0x45, 0x6f, 0x5d,
            0x61, 0x18, 0xd4, 0xfe, 0xe0, 0xd6,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_hmac_sha1(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA1 as i64);
    }

    #[test]
    fn test_hmac_sha224() {
        let inp = [0x41u8; 16];
        let key = [0u8; 16];
        let out = [0u8; SIZE_SHA224 as usize];
        let out_exp = [
            0x5d, 0x8c, 0x6c, 0x1f, 0xf2, 0x97, 0xbf, 0x59, 0x3f, 0x59, 0x1c, 0xf3, 0x4d, 0x3c,
            0x96, 0x36, 0xde, 0x33, 0x11, 0x5f, 0xb1, 0x3e, 0xa5, 0x75, 0x8c, 0xfc, 0xdc, 0x6,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_hmac_sha224(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA224 as i64);
    }

    #[test]
    fn test_hmac_sha256() {
        let inp = [0x41u8; 16];
        let key = [0u8; 16];
        let out = [0u8; SIZE_SHA256 as usize];
        let out_exp = [
            0x4a, 0x81, 0xd6, 0x13, 0xb0, 0xe, 0x91, 0x9e, 0x8a, 0xd9, 0x63, 0x78, 0x88, 0xe6,
            0xa4, 0xfe, 0x8, 0x22, 0x4a, 0xb6, 0x48, 0x4b, 0xa, 0x37, 0x47, 0xa6, 0xa6, 0x62, 0xb6,
            0xa2, 0x99, 0xd,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_hmac_sha256(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA256 as i64);
    }

    #[test]
    fn test_hmac_sha384() {
        let inp = [0x41u8; 16];
        let key = [0u8; 16];
        let out = [0u8; SIZE_SHA384 as usize];
        let out_exp = [
            0x1b, 0xcc, 0x5, 0x6f, 0x74, 0xc9, 0x34, 0xce, 0x5f, 0xe, 0xc4, 0xf5, 0x45, 0x3d, 0x1c,
            0xef, 0x7c, 0x1b, 0x8d, 0xae, 0xa7, 0x6d, 0xe7, 0xc7, 0x9e, 0x7e, 0xe, 0x68, 0x4e,
            0x95, 0x6d, 0xd8, 0x52, 0x11, 0x20, 0xd, 0x99, 0x93, 0x63, 0x89, 0x4f, 0xfd, 0x37, 0xc,
            0xdd, 0x27, 0x75, 0xc8,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_hmac_sha384(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA384 as i64);
    }

    #[test]
    fn test_hmac_sha512() {
        let inp = [0x41u8; 16];
        let key = [0u8; 16];
        let out = [0u8; SIZE_SHA512 as usize];
        let out_exp = [
            0x44, 0xdb, 0xf1, 0xae, 0x7d, 0xcd, 0xc0, 0x5f, 0xa6, 0x9b, 0x30, 0x44, 0x99, 0xfa,
            0x19, 0x82, 0x40, 0xb, 0x94, 0xc0, 0xe9, 0x9, 0xcb, 0xc5, 0xf5, 0x74, 0x66, 0x84, 0x45,
            0x5b, 0x31, 0xf8, 0x8e, 0x94, 0x14, 0x8c, 0xe2, 0xa4, 0x7, 0xa7, 0x58, 0xd2, 0x14,
            0x11, 0x85, 0x8b, 0xa4, 0x50, 0x4c, 0xaa, 0x2e, 0xa1, 0x70, 0xa3, 0x1b, 0xec, 0x87,
            0xab, 0xb6, 0x54, 0xf4, 0xe9, 0xd, 0x48,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_md_hmac_sha512(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(out_exp, out);
        assert_eq!(ret, SIZE_SHA512 as i64);
    }

    #[test]
    fn test_aes128_cbc_enc() {
        let inp = [0x41u8; AES_BLOCKSIZE as usize];
        let key = [0u8; AES128_KEYSIZE as usize];
        let iv = [0u8; AES128_KEYSIZE as usize];

        let out = [0u8; AES_BLOCKSIZE as usize];
        let out_exp = [
            0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
            0x63, 0xe3,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_cbc(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(ret, inp.len() as i64);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes128_cbc_dec() {
        let inp = [
            0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
            0x63, 0xe3,
        ];
        let key = [0u8; AES128_KEYSIZE as usize];
        let iv = [0u8; AES128_KEYSIZE as usize];

        let out = [0u8; AES_BLOCKSIZE as usize];
        let out_exp = [0x41u8; AES_BLOCKSIZE as usize];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_dec_aes_cbc(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(ret, inp.len() as i64);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes192_cbc_enc() {
        let inp = [0x41u8; AES_BLOCKSIZE as usize];
        let key = [0u8; AES192_KEYSIZE as usize];
        let iv = [0u8; AES192_KEYSIZE as usize];

        let out = [0u8; AES_BLOCKSIZE as usize];
        let out_exp = [
            0x48, 0x5e, 0x40, 0x47, 0x1, 0xda, 0x67, 0x88, 0x74, 0x72, 0x4d, 0x32, 0xda, 0x51,
            0xd1, 0x24,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_cbc(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(ret, inp.len() as i64);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes192_cbc_dec() {
        let inp = [
            0x48, 0x5e, 0x40, 0x47, 0x1, 0xda, 0x67, 0x88, 0x74, 0x72, 0x4d, 0x32, 0xda, 0x51,
            0xd1, 0x24,
        ];
        let key = [0u8; AES192_KEYSIZE as usize];
        let iv = [0u8; AES192_KEYSIZE as usize];

        let out = [0u8; AES_BLOCKSIZE as usize];
        let out_exp = [0x41u8; AES_BLOCKSIZE as usize];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_dec_aes_cbc(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(ret, inp.len() as i64);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes256_cbc_enc() {
        let inp = [0x41u8; AES_BLOCKSIZE as usize];
        let key = [0u8; AES256_KEYSIZE as usize];
        let iv = [0u8; AES256_KEYSIZE as usize];

        let out = [0u8; AES_BLOCKSIZE as usize];
        let out_exp = [
            0x7e, 0xe, 0x75, 0x77, 0xef, 0x9c, 0x30, 0xa6, 0xbf, 0xb, 0x25, 0xe0, 0x62, 0x1e, 0x82,
            0x7e,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_cbc(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(ret, inp.len() as i64);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes256_cbc_dec() {
        let inp = [
            0x7e, 0xe, 0x75, 0x77, 0xef, 0x9c, 0x30, 0xa6, 0xbf, 0xb, 0x25, 0xe0, 0x62, 0x1e, 0x82,
            0x7e,
        ];
        let key = [0u8; AES256_KEYSIZE as usize];
        let iv = [0u8; AES256_KEYSIZE as usize];

        let out = [0u8; AES_BLOCKSIZE as usize];
        let out_exp = [0x41u8; AES_BLOCKSIZE as usize];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_dec_aes_cbc(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(ret, inp.len() as i64);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes128_ctr_enc() {
        let inp = [0x41u8; (AES_BLOCKSIZE * 2) as usize];
        let key = [0u8; AES128_KEYSIZE as usize];
        let iv = [0u8; AES128_KEYSIZE as usize];

        let out = [0u8; (AES_BLOCKSIZE * 2) as usize];
        let out_exp = [
            0x27, 0xa8, 0xa, 0x95, 0xae, 0xcb, 0x6d, 0x7a, 0xc9, 0xd, 0xbb, 0x18, 0x8b, 0x75, 0x6a,
            0x6f, 0x19, 0xa3, 0xbd, 0x8f, 0xbb, 0x3f, 0x71, 0x20, 0x77, 0x3e, 0x5c, 0x16, 0xe5,
            0xa6, 0x4, 0x1b,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_ctr(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(inp.len() as i64, ret);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes128_ctr_dec() {
        let inp = [
            0x27, 0xa8, 0xa, 0x95, 0xae, 0xcb, 0x6d, 0x7a, 0xc9, 0xd, 0xbb, 0x18, 0x8b, 0x75, 0x6a,
            0x6f, 0x19, 0xa3, 0xbd, 0x8f, 0xbb, 0x3f, 0x71, 0x20, 0x77, 0x3e, 0x5c, 0x16, 0xe5,
            0xa6, 0x4, 0x1b,
        ];
        let key = [0u8; AES128_KEYSIZE as usize];
        let iv = [0u8; AES128_KEYSIZE as usize];

        let out = [0u8; (AES_BLOCKSIZE * 2) as usize];
        let out_exp = [0x41u8; (AES_BLOCKSIZE * 2) as usize];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_ctr(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }
        assert_eq!(inp.len() as i64, ret);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes192_ctr_enc() {
        let inp = [0x41u8; (AES_BLOCKSIZE * 2) as usize];
        let key = [0u8; AES192_KEYSIZE as usize];
        let iv = [0u8; AES192_KEYSIZE as usize];

        let out = [0u8; (AES_BLOCKSIZE * 2) as usize];
        let out_exp = [
            0xeb, 0xa1, 0x28, 0xd3, 0xed, 0xfe, 0x13, 0xe2, 0xa9, 0xb5, 0xe8, 0x2f, 0x88, 0x71,
            0x4a, 0x96, 0x8c, 0x72, 0xf3, 0xcb, 0x86, 0x32, 0xb6, 0xa, 0xe1, 0x4f, 0x90, 0xb2,
            0x53, 0x16, 0x65, 0x74,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_ctr(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(inp.len() as i64, ret);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes192_ctr_dec() {
        let inp = [
            0xeb, 0xa1, 0x28, 0xd3, 0xed, 0xfe, 0x13, 0xe2, 0xa9, 0xb5, 0xe8, 0x2f, 0x88, 0x71,
            0x4a, 0x96, 0x8c, 0x72, 0xf3, 0xcb, 0x86, 0x32, 0xb6, 0xa, 0xe1, 0x4f, 0x90, 0xb2,
            0x53, 0x16, 0x65, 0x74,
        ];
        let key = [0u8; AES192_KEYSIZE as usize];
        let iv = [0u8; AES192_KEYSIZE as usize];

        let out = [0u8; (AES_BLOCKSIZE * 2) as usize];
        let out_exp = [0x41u8; (AES_BLOCKSIZE * 2) as usize];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_ctr(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }
        assert_eq!(inp.len() as i64, ret);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes256_ctr_enc() {
        let inp = [0x41u8; (AES_BLOCKSIZE * 2) as usize];
        let key = [0u8; AES256_KEYSIZE as usize];
        let iv = [0u8; AES256_KEYSIZE as usize];

        let out = [0u8; (AES_BLOCKSIZE * 2) as usize];
        let out_exp = [
            0x9d, 0xd4, 0x81, 0x39, 0xe3, 0x1, 0xc8, 0xc8, 0xec, 0x9, 0xe3, 0x55, 0xd3, 0xc5, 0x61,
            0xc6, 0x12, 0x4e, 0xcb, 0xba, 0x86, 0x4, 0x77, 0xf8, 0xe8, 0x22, 0xf5, 0xb0, 0x85,
            0x8a, 0x32, 0xca,
        ];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_ctr(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }

        assert_eq!(inp.len() as i64, ret);
        assert_eq!(out_exp, out);
    }

    #[test]
    fn test_aes256_ctr_dec() {
        let inp = [
            0x9d, 0xd4, 0x81, 0x39, 0xe3, 0x1, 0xc8, 0xc8, 0xec, 0x9, 0xe3, 0x55, 0xd3, 0xc5, 0x61,
            0xc6, 0x12, 0x4e, 0xcb, 0xba, 0x86, 0x4, 0x77, 0xf8, 0xe8, 0x22, 0xf5, 0xb0, 0x85,
            0x8a, 0x32, 0xca,
        ];
        let key = [0u8; AES256_KEYSIZE as usize];
        let iv = [0u8; AES256_KEYSIZE as usize];

        let out = [0u8; (AES_BLOCKSIZE * 2) as usize];
        let out_exp = [0x41u8; (AES_BLOCKSIZE * 2) as usize];

        let ret: i64;
        unsafe {
            ret = kcapi_cipher_enc_aes_ctr(
                key.as_ptr(),
                key.len() as u32,
                inp.as_ptr(),
                (inp.len() as u32).into(),
                iv.as_ptr(),
                out.as_ptr() as *mut u8,
                (out.len() as u32).into(),
            );
        }
        assert_eq!(inp.len() as i64, ret);
        assert_eq!(out_exp, out);
    }
}
