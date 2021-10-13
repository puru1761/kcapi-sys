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
pub mod tests {
    use std::convert::TryInto;
    use std::ffi::CString;

    use crate::{
        kcapi_aead_decrypt, kcapi_aead_encrypt, kcapi_aead_inbuflen_dec, kcapi_aead_inbuflen_enc,
        kcapi_aead_init, kcapi_aead_outbuflen_dec, kcapi_aead_outbuflen_enc,
        kcapi_aead_setassoclen, kcapi_aead_setkey, kcapi_aead_settaglen, kcapi_handle,
        kcapi_pad_iv, AES128_KEYSIZE, AES_BLOCKSIZE, KCAPI_ACCESS_HEURISTIC,
    };

    #[test]
    fn test_aead_encrypt() {
        const pt: [u8; AES_BLOCKSIZE as usize] = [
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41,
        ];
        const assocdata: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut ct = [0u8; pt.len()];
        const ct_exp: [u8; pt.len()] = [
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39,
        ];
        const taglen: usize = 16;
        const assoclen: usize = assocdata.len();

        let mut tag = [0u8; taglen];
        const tag_exp: [u8; taglen] = [
            0x10, 0x8f, 0x8e, 0x8f, 0x78, 0xdd, 0x83, 0xd0, 0xf, 0xe2, 0xa2, 0x79, 0xc3, 0xce,
            0xb2, 0x43,
        ];

        let key = [0u8; AES128_KEYSIZE as usize];
        let iv = [0u8; AES_BLOCKSIZE as usize];
        let alg = CString::new("gcm(aes)").expect("Failed to init CString");

        let mut outbuf = [0u8; pt.len() + taglen + assoclen];
        let assocdata_offset: usize = 0;
        let ct_offset = assocdata_offset + assoclen;
        let tag_offset = ct_offset + taglen;

        outbuf[assocdata_offset..ct_offset].clone_from_slice(&assocdata);
        outbuf[ct_offset..tag_offset].clone_from_slice(&pt);

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_aead_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = (kcapi_aead_settaglen(handle, taglen as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            kcapi_aead_setassoclen(handle, assoclen as u64);

            let mut newiv = &mut [0u8; 48] as *mut u8;
            let mut newivlen: u32 = 0;
            ret = (kcapi_pad_iv(
                handle,
                iv.as_ptr(),
                iv.len() as u32,
                &mut newiv as *mut _,
                &mut newivlen as *mut u32,
            ))
            .try_into()
            .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            let outbuflen =
                kcapi_aead_outbuflen_enc(handle, pt.len() as u64, assoclen as u64, taglen as u64);
            let inbuflen =
                kcapi_aead_inbuflen_enc(handle, pt.len() as u64, assoclen as u64, taglen as u64);

            ret = (kcapi_aead_setkey(handle, key.as_ptr(), key.len() as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_aead_encrypt(
                handle,
                outbuf.as_ptr(),
                inbuflen,
                newiv,
                outbuf.as_mut_ptr(),
                outbuflen,
                KCAPI_ACCESS_HEURISTIC as i32,
            );
            assert_eq!(ret, outbuf.len() as i64);

            ct.clone_from_slice(&outbuf[assocdata.len()..assocdata.len() + pt.len()]);
            tag.clone_from_slice(&outbuf[tag_offset..]);
        }
        assert_eq!(ct, ct_exp);
        assert_eq!(tag, tag_exp);
    }

    #[test]
    fn test_aead_decrypt() {
        const ct: [u8; AES_BLOCKSIZE as usize] = [
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39,
        ];

        const tag: [u8; taglen] = [
            0x10, 0x8f, 0x8e, 0x8f, 0x78, 0xdd, 0x83, 0xd0, 0xf, 0xe2, 0xa2, 0x79, 0xc3, 0xce,
            0xb2, 0x43,
        ];
        const assocdata: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        const taglen: usize = 16;
        const assoclen: usize = assocdata.len();

        let mut pt = [0u8; ct.len()];
        const pt_exp: [u8; 16] = [
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41,
        ];

        let key = [0u8; AES128_KEYSIZE as usize];
        let iv = [0u8; AES_BLOCKSIZE as usize];
        let alg = CString::new("gcm(aes)").expect("Failed to init CString");

        let mut outbuf = [0u8; ct.len() + taglen + assoclen];
        let assocdata_offset: usize = 0;
        let ct_offset = assocdata_offset + assoclen;
        let tag_offset = ct_offset + taglen;

        outbuf[assocdata_offset..ct_offset].clone_from_slice(&assocdata);
        outbuf[ct_offset..tag_offset].clone_from_slice(&ct);
        outbuf[tag_offset..].clone_from_slice(&tag);

        let mut ret: i64;
        unsafe {
            let mut handle =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;

            ret = (kcapi_aead_init(&mut handle as *mut _, alg.as_ptr(), 0))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = (kcapi_aead_settaglen(handle, taglen as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            kcapi_aead_setassoclen(handle, assoclen as u64);

            let mut newiv = &mut [0u8; 48] as *mut u8;
            let mut newivlen: u32 = 0;
            ret = (kcapi_pad_iv(
                handle,
                iv.as_ptr(),
                iv.len() as u32,
                &mut newiv as *mut _,
                &mut newivlen as *mut u32,
            ))
            .try_into()
            .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            let inbuflen =
                kcapi_aead_inbuflen_dec(handle, ct.len() as u64, assoclen as u64, taglen as u64);
            let outbuflen =
                kcapi_aead_outbuflen_dec(handle, ct.len() as u64, assoclen as u64, taglen as u64);

            ret = (kcapi_aead_setkey(handle, key.as_ptr(), key.len() as u32))
                .try_into()
                .expect("Failed to convert i32 to i64");
            assert_eq!(ret, 0);

            ret = kcapi_aead_decrypt(
                handle,
                outbuf.as_ptr(),
                inbuflen,
                newiv,
                outbuf.as_mut_ptr(),
                outbuflen,
                KCAPI_ACCESS_HEURISTIC as i32,
            );
            assert_eq!(ret, (outbuf.len() - assoclen) as i64);

            pt.clone_from_slice(&outbuf[assocdata.len()..assocdata.len() + ct.len()]);
        }
        assert_eq!(pt, pt_exp);
    }
}
