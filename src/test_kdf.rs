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
    use std::ffi::CString;

    #[test]
    fn test_ctr_kdf() {
        const CTR_KDF_KEY: [u8; 32] = [
            0xdd, 0x1d, 0x91, 0xb7, 0xd9, 0xb, 0x2b, 0xd3, 0x13, 0x85, 0x33, 0xce, 0x92, 0xb2,
            0x72, 0xfb, 0xf8, 0xa3, 0x69, 0x31, 0x6a, 0xef, 0xe2, 0x42, 0xe6, 0x59, 0xcc, 0xa,
            0xe2, 0x38, 0xaf, 0xe0,
        ];

        const CTR_KDF_MSG: [u8; 60] = [
            0x1, 0x32, 0x2b, 0x96, 0xb3, 0xa, 0xcd, 0x19, 0x79, 0x79, 0x44, 0x4e, 0x46, 0x8e, 0x1c,
            0x5c, 0x68, 0x59, 0xbf, 0x1b, 0x1c, 0xf9, 0x51, 0xb7, 0xe7, 0x25, 0x30, 0x3e, 0x23,
            0x7e, 0x46, 0xb8, 0x64, 0xa1, 0x45, 0xfa, 0xb2, 0x5e, 0x51, 0x7b, 0x8, 0xf8, 0x68,
            0x3d, 0x3, 0x15, 0xbb, 0x29, 0x11, 0xd8, 0xa, 0xe, 0x8a, 0xba, 0x17, 0xf3, 0xb4, 0x13,
            0xfa, 0xac,
        ];

        const CTR_KDF_EXP: [u8; 16] = [
            0x10, 0x62, 0x13, 0x42, 0xbf, 0xb0, 0xfd, 0x40, 0x4, 0x6c, 0xe, 0x29, 0xf2, 0xcf, 0xdb,
            0xf0,
        ];

        let mut out = [0u8; 16];

        let alg = CString::new("hmac(sha256)").expect("Failed to allocate CString");
        unsafe {
            let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
                as *mut crate::kcapi_handle;
            let mut ret = crate::kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), 0);
            assert_eq!(ret, 0);

            ret = crate::kcapi_md_setkey(handle, CTR_KDF_KEY.as_ptr(), CTR_KDF_KEY.len() as u32);
            assert_eq!(ret, 0);

            let ret = crate::kcapi_kdf_ctr(
                handle,
                CTR_KDF_MSG.as_ptr(),
                CTR_KDF_MSG.len() as crate::size_t,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(CTR_KDF_EXP, out);
        }
    }

    #[test]
    fn test_fb_kdf() {
        const FB_KDF_KEY: [u8; 32] = [
            0x93, 0xf6, 0x98, 0xe8, 0x42, 0xee, 0xd7, 0x53, 0x94, 0xd6, 0x29, 0xd9, 0x57, 0xe2,
            0xe8, 0x9c, 0x6e, 0x74, 0x1f, 0x81, 0xb, 0x62, 0x3c, 0x8b, 0x90, 0x1e, 0x38, 0x37,
            0x6d, 0x6, 0x8e, 0x7b,
        ];

        const FB_KDF_MSG: [u8; 83] = [
            0x9f, 0x57, 0x5d, 0x90, 0x59, 0xd3, 0xe0, 0xc0, 0x80, 0x3f, 0x8, 0x11, 0x2f, 0x8a,
            0x80, 0x6d, 0xe3, 0xc3, 0x47, 0x19, 0x12, 0xcd, 0xf4, 0x2b, 0x9, 0x53, 0x88, 0xb1,
            0x4b, 0x33, 0x50, 0x8e, 0x53, 0xb8, 0x9c, 0x18, 0x69, 0xe, 0x20, 0x57, 0xa1, 0xd1,
            0x67, 0x82, 0x2e, 0x63, 0x6d, 0xe5, 0xb, 0xe0, 0x1, 0x85, 0x32, 0xc4, 0x31, 0xf7, 0xf5,
            0xe3, 0x7f, 0x77, 0x13, 0x92, 0x20, 0xd5, 0xe0, 0x42, 0x59, 0x9e, 0xbe, 0x26, 0x6a,
            0xf5, 0x76, 0x7e, 0xe1, 0x8c, 0xd2, 0xc5, 0xc1, 0x9a, 0x1f, 0xf, 0x80,
        ];

        const FB_KDF_EXP: [u8; 64] = [
            0xbd, 0x14, 0x76, 0xf4, 0x3a, 0x4e, 0x31, 0x57, 0x47, 0xcf, 0x59, 0x18, 0xe0, 0xea,
            0x5b, 0xc0, 0xd9, 0x87, 0x69, 0x45, 0x74, 0x77, 0xc3, 0xab, 0x18, 0xb7, 0x42, 0xde,
            0xf0, 0xe0, 0x79, 0xa9, 0x33, 0xb7, 0x56, 0x36, 0x5a, 0xfb, 0x55, 0x41, 0xf2, 0x53,
            0xfe, 0xe4, 0x3c, 0x6f, 0xd7, 0x88, 0xa4, 0x40, 0x41, 0x3, 0x85, 0x9, 0xe9, 0xee, 0xb6,
            0x8f, 0x7d, 0x65, 0xff, 0xbb, 0x5f, 0x95,
        ];

        let mut out = [0u8; 64];

        let alg = CString::new("hmac(sha256)").expect("Failed to allocate CString");
        unsafe {
            let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
                as *mut crate::kcapi_handle;
            let mut ret = crate::kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), 0);
            assert_eq!(ret, 0);

            ret = crate::kcapi_md_setkey(handle, FB_KDF_KEY.as_ptr(), FB_KDF_KEY.len() as u32);
            assert_eq!(ret, 0);

            let ret = crate::kcapi_kdf_fb(
                handle,
                FB_KDF_MSG.as_ptr(),
                FB_KDF_MSG.len() as crate::size_t,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(FB_KDF_EXP, out);
        }
    }

    #[test]
    fn test_dpi_kdf() {
        const DPI_KDF_KEY: [u8; 32] = [
            0x2, 0xd3, 0x6f, 0xa0, 0x21, 0xc2, 0xd, 0xdb, 0xde, 0xe4, 0x69, 0xf0, 0x57, 0x94, 0x68,
            0xba, 0xe5, 0xcb, 0x13, 0xb5, 0x48, 0xb6, 0xc6, 0x1c, 0xdf, 0x9d, 0x3e, 0xc4, 0x19,
            0x11, 0x1d, 0xe2,
        ];

        const DPI_KDF_MSG: [u8; 51] = [
            0x85, 0xab, 0xe3, 0x8b, 0xf2, 0x65, 0xfb, 0xdc, 0x64, 0x45, 0xae, 0x5c, 0x71, 0x15,
            0x9f, 0x15, 0x48, 0xc7, 0x3b, 0x7d, 0x52, 0x6a, 0x62, 0x31, 0x4, 0x90, 0x4a, 0xf, 0x87,
            0x92, 0x7, 0xb, 0x3d, 0xf9, 0x90, 0x2b, 0x96, 0x69, 0x49, 0x4, 0x25, 0xa3, 0x85, 0xea,
            0xdb, 0xf, 0x9c, 0x76, 0xe4, 0x6f, 0xf,
        ];

        const DPI_KDF_EXP: [u8; 64] = [
            0xd6, 0x9f, 0x74, 0xf5, 0x18, 0xc9, 0xf6, 0x4f, 0x90, 0xa0, 0xbe, 0xeb, 0xab, 0x69,
            0xf6, 0x89, 0xb7, 0x3b, 0x5c, 0x13, 0xeb, 0xf, 0x86, 0xa, 0x95, 0xca, 0xd7, 0xd9, 0x81,
            0x4f, 0x8c, 0x50, 0x6e, 0xb7, 0xb1, 0x79, 0xa5, 0xc5, 0xb4, 0x46, 0x6a, 0x9e, 0xc1,
            0x54, 0xc3, 0xbf, 0x1c, 0x13, 0xef, 0xd6, 0xec, 0xd, 0x82, 0xb0, 0x2c, 0x29, 0xaf,
            0x2c, 0x69, 0x2, 0x99, 0xed, 0xc4, 0x53,
        ];

        let mut out = [0u8; 64];

        let alg = CString::new("hmac(sha256)").expect("Failed to allocate CString");
        unsafe {
            let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
                as *mut crate::kcapi_handle;
            let mut ret = crate::kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), 0);
            assert_eq!(ret, 0);

            ret = crate::kcapi_md_setkey(handle, DPI_KDF_KEY.as_ptr(), DPI_KDF_KEY.len() as u32);
            assert_eq!(ret, 0);

            let ret = crate::kcapi_kdf_dpi(
                handle,
                DPI_KDF_MSG.as_ptr(),
                DPI_KDF_MSG.len() as crate::size_t,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(DPI_KDF_EXP, out);
        }
    }

    #[test]
    fn test_hkdf() {
        const HKDF_IKM: [u8; 22] = [
            0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
            0xb, 0xb, 0xb, 0xb, 0xb,
        ];

        const HKDF_SALT: [u8; 13] = [
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc,
        ];

        const HKDF_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        const HKDF_OUT_EXP: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0xa, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x0, 0x72, 0x8, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut out = [0u8; 42];

        let alg = CString::new("hmac(sha256)").expect("Failed to allocate CString");
        unsafe {
            let ret = crate::kcapi_hkdf(
                alg.as_ptr(),
                HKDF_IKM.as_ptr(),
                HKDF_IKM.len() as crate::size_t,
                HKDF_SALT.as_ptr(),
                HKDF_SALT.len() as u32,
                HKDF_INFO.as_ptr(),
                HKDF_INFO.len() as crate::size_t,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(out, HKDF_OUT_EXP);
        }
    }

    #[test]
    fn test_pbkdf_one_loop() {
        const PBKDF_SALT: [u8; 4] = [0x73, 0x61, 0x6c, 0x74];
        const PBKDF_PASSWORD: [u8; 8] = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        const PBKDF_EXP: [u8; 20] = [
            0xc, 0x60, 0xc8, 0xf, 0x96, 0x1f, 0xe, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12,
            0x6, 0x2f, 0xe0, 0x37, 0xa6,
        ];
        const LOOPS: u32 = 1;

        let mut out = [0u8; 20];
        let alg = CString::new("hmac(sha1)").expect("Failed to allocate CString");
        unsafe {
            let ret = crate::kcapi_pbkdf(
                alg.as_ptr(),
                PBKDF_PASSWORD.as_ptr(),
                PBKDF_PASSWORD.len() as u32,
                PBKDF_SALT.as_ptr(),
                PBKDF_SALT.len() as crate::size_t,
                LOOPS,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(out, PBKDF_EXP);
        }
    }

    #[test]
    fn test_pbkdf_two_loops() {
        const PBKDF_SALT: [u8; 4] = [0x73, 0x61, 0x6c, 0x74];
        const PBKDF_PASSWORD: [u8; 8] = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        const PBKDF_EXP: [u8; 20] = [
            0xea, 0x6c, 0x1, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
            0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        const LOOPS: u32 = 2;

        let mut out = [0u8; 20];
        let alg = CString::new("hmac(sha1)").expect("Failed to allocate CString");
        unsafe {
            let ret = crate::kcapi_pbkdf(
                alg.as_ptr(),
                PBKDF_PASSWORD.as_ptr(),
                PBKDF_PASSWORD.len() as u32,
                PBKDF_SALT.as_ptr(),
                PBKDF_SALT.len() as crate::size_t,
                LOOPS,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(out, PBKDF_EXP);
        }
    }

    #[test]
    fn test_pbkdf_4k_loops() {
        const PBKDF_SALT: [u8; 4] = [0x73, 0x61, 0x6c, 0x74];
        const PBKDF_PASSWORD: [u8; 8] = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        const PBKDF_EXP: [u8; 20] = [
            0x4b, 0x0, 0x79, 0x1, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21,
            0xd0, 0x65, 0xa4, 0x29, 0xc1,
        ];
        const LOOPS: u32 = 4096;

        let mut out = [0u8; 20];
        let alg = CString::new("hmac(sha1)").expect("Failed to allocate CString");
        unsafe {
            let ret = crate::kcapi_pbkdf(
                alg.as_ptr(),
                PBKDF_PASSWORD.as_ptr(),
                PBKDF_PASSWORD.len() as u32,
                PBKDF_SALT.as_ptr(),
                PBKDF_SALT.len() as crate::size_t,
                LOOPS,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(out, PBKDF_EXP);
        }
    }

    #[test]
    fn test_pbkdf_multiloop() {
        const PBKDF_SALT: [u8; 4] = [0x73, 0x61, 0x6c, 0x74];
        const PBKDF_PASSWORD: [u8; 8] = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        const PBKDF_EXP: [u8; 20] = [
            0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2,
            0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84,
        ];
        const LOOPS: u32 = 16777216;

        let mut out = [0u8; 20];
        let alg = CString::new("hmac(sha1)").expect("Failed to allocate CString");
        unsafe {
            let ret = crate::kcapi_pbkdf(
                alg.as_ptr(),
                PBKDF_PASSWORD.as_ptr(),
                PBKDF_PASSWORD.len() as u32,
                PBKDF_SALT.as_ptr(),
                PBKDF_SALT.len() as crate::size_t,
                LOOPS,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(out, PBKDF_EXP);
        }
    }

    #[test]
    fn test_pbkdf_128_bit_key() {
        const PBKDF_SALT: [u8; 5] = [0x73, 0x61, 0x00, 0x6c, 0x74];
        const PBKDF_PASSWORD: [u8; 9] = [0x70, 0x61, 0x73, 0x73, 0x00, 0x77, 0x6f, 0x72, 0x64];
        const PBKDF_EXP: [u8; 16] = [
            0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x9, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25,
            0xe0, 0xc3,
        ];
        const LOOPS: u32 = 4096;

        let mut out = [0u8; 16];
        let alg = CString::new("hmac(sha1)").expect("Failed to allocate CString");
        unsafe {
            let ret = crate::kcapi_pbkdf(
                alg.as_ptr(),
                PBKDF_PASSWORD.as_ptr(),
                PBKDF_PASSWORD.len() as u32,
                PBKDF_SALT.as_ptr(),
                PBKDF_SALT.len() as crate::size_t,
                LOOPS,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(out, PBKDF_EXP);
        }
    }

    #[test]
    fn test_pbkdf_200_bit_key() {
        const PBKDF_SALT: [u8; 36] = [
            0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74, 0x53, 0x41,
            0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74,
            0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74,
        ];
        const PBKDF_PASSWORD: [u8; 24] = [
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x50, 0x41, 0x53, 0x53, 0x57, 0x4f,
            0x52, 0x44, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
        ];
        const PBKDF_EXP: [u8; 25] = [
            0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0,
            0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38,
        ];
        const LOOPS: u32 = 4096;

        let alg = CString::new("hmac(sha1)").expect("Failed to allocate CString");
        let mut out = [0u8; 25];
        unsafe {
            let ret = crate::kcapi_pbkdf(
                alg.as_ptr(),
                PBKDF_PASSWORD.as_ptr(),
                PBKDF_PASSWORD.len() as u32,
                PBKDF_SALT.as_ptr(),
                PBKDF_SALT.len() as crate::size_t,
                LOOPS,
                out.as_mut_ptr(),
                out.len() as crate::size_t,
            );
            assert_eq!(ret, 0);
            assert_eq!(out, PBKDF_EXP);
        }
    }
}
