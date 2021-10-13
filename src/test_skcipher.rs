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

#[cfg(test)]
mod tests {
    use std::{convert::TryInto, ffi::CString};

    use crate::{
        kcapi_cipher_dec_aes_cbc, kcapi_cipher_dec_aes_ctr, kcapi_cipher_decrypt,
        kcapi_cipher_enc_aes_cbc, kcapi_cipher_enc_aes_ctr, kcapi_cipher_encrypt,
        kcapi_cipher_init, kcapi_cipher_setkey, kcapi_handle, AES128_KEYSIZE, AES192_KEYSIZE,
        AES256_KEYSIZE, AES_BLOCKSIZE, KCAPI_ACCESS_HEURISTIC,
    };

    #[test]
    fn test_kcapi_skcipher_enc() {
        let pt = [0x41u8; AES_BLOCKSIZE as usize];
        let mut ct = [0u8; AES_BLOCKSIZE as usize];
        let key = [0u8; AES256_KEYSIZE as usize];
        let iv = [0u8; AES_BLOCKSIZE as usize];
        let alg = CString::new("cbc(aes)").expect("Failed to convert to Cstring");

        let ct_exp = [
            0x7e, 0xe, 0x75, 0x77, 0xef, 0x9c, 0x30, 0xa6, 0xbf, 0xb, 0x25, 0xe0, 0x62, 0x1e, 0x82,
            0x7e,
        ];

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_cipher_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = (kcapi_cipher_setkey(handle, key.as_ptr(), key.len() as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_cipher_encrypt(
                handle,
                pt.as_ptr(),
                pt.len() as u64,
                iv.as_ptr(),
                ct.as_mut_ptr(),
                ct.len() as u64,
                KCAPI_ACCESS_HEURISTIC as i32,
            );
            assert_eq!(ret, pt.len() as i64);
        }
        assert_eq!(ct_exp, ct);
    }

    #[test]
    fn test_kcapi_skcipher_dec() {
        let ct = [
            0x7e, 0xe, 0x75, 0x77, 0xef, 0x9c, 0x30, 0xa6, 0xbf, 0xb, 0x25, 0xe0, 0x62, 0x1e, 0x82,
            0x7e,
        ];
        let mut pt = [0u8; AES_BLOCKSIZE as usize];
        let key = [0u8; AES256_KEYSIZE as usize];
        let iv = [0u8; AES_BLOCKSIZE as usize];
        let alg = CString::new("cbc(aes)").expect("Failed to convert to Cstring");

        let pt_exp = [0x41u8; AES_BLOCKSIZE as usize];

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_cipher_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = (kcapi_cipher_setkey(handle, key.as_ptr(), key.len() as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_cipher_decrypt(
                handle,
                ct.as_ptr(),
                ct.len() as u64,
                iv.as_ptr(),
                pt.as_mut_ptr(),
                pt.len() as u64,
                KCAPI_ACCESS_HEURISTIC as i32,
            );
            assert_eq!(ret, pt.len() as i64);
        }
        assert_eq!(pt_exp, pt);
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
            ret = kcapi_cipher_dec_aes_ctr(
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
            ret = kcapi_cipher_dec_aes_ctr(
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
            ret = kcapi_cipher_dec_aes_ctr(
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
