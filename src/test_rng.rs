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
        kcapi_handle, kcapi_rng_destroy, kcapi_rng_generate, kcapi_rng_get_bytes, kcapi_rng_init,
        kcapi_rng_seed, kcapi_rng_setentropy,
    };

    #[test]
    fn test_rng_generate() {
        let mut seed = [0x41u8; 16];
        let mut out = [0u8; 16];
        let alg = CString::new("drbg_nopr_sha1").expect("Unable to create CString");

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_rng_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = (kcapi_rng_seed(handle, seed.as_mut_ptr(), seed.len() as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_rng_generate(handle, out.as_mut_ptr(), out.len() as u64);
            assert_eq!(ret, out.len() as i64);

            kcapi_rng_destroy(handle);
        }
    }

    #[test]
    fn test_rng_get_bytes() {
        let mut out = [0u8; 16];
        let mut out_next = [0u8; 16];

        let mut ret: i64;
        unsafe {
            ret = kcapi_rng_get_bytes(out.as_mut_ptr(), out.len() as u64);
            assert_eq!(ret, out.len() as i64);

            ret = kcapi_rng_get_bytes(out_next.as_mut_ptr(), out_next.len() as u64);
            assert_eq!(ret, out_next.len() as i64);

            assert_ne!(out, out_next);
        }
    }

    #[test]
    #[ignore]
    fn test_rng_setentropy() {
        let mut ent = [0x41u8; 16];
        let mut seed = [0x41u8; 16];
        let mut out = [0u8; 16];
        let alg = CString::new("drbg_nopr_sha1").expect("Unable to create CString");

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_rng_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_rng_setentropy(handle, ent.as_mut_ptr(), ent.len() as u32)
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_rng_seed(handle, seed.as_mut_ptr(), seed.len() as u32)
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_rng_generate(handle, out.as_mut_ptr(), 16);
            assert_eq!(ret, 16);
        }
    }

    #[test]
    #[ignore]
    fn test_rng_kat() {
        let mut ent = [0x41u8; 16];
        let mut seed = [0x41u8; 16];
        let mut out = [0u8; 16];
        let out_exp = [
            0xbd, 0x3a, 0xbb, 0xfe, 0x98, 0x85, 0x69, 0xbf, 0x64, 0x2f, 0xe9, 0xb3, 0x55, 0xc1,
            0xc0, 0x35,
        ];
        let alg = CString::new("drbg_nopr_sha1").expect("Unable to create CString");

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_rng_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_rng_setentropy(handle, ent.as_mut_ptr(), ent.len() as u32)
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_rng_seed(handle, seed.as_mut_ptr(), seed.len() as u32)
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_rng_generate(handle, out.as_mut_ptr(), 16);
            assert_eq!(ret, 16);
            assert_eq!(out, out_exp);
        }
    }
}
