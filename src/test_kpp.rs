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

    use crate::{
        kcapi_handle, kcapi_kpp_destroy, kcapi_kpp_ecdh_setcurve, kcapi_kpp_init, kcapi_kpp_keygen,
        kcapi_kpp_setkey, kcapi_kpp_ssgen, ECC_CURVE_NIST_P256, KCAPI_ACCESS_HEURISTIC,
    };

    // The KPP AF_ALG interface (`algif_kpp`) is not part of the upstream Linux
    // kernel; it requires the out-of-tree patches shipped under `kernel-patches`.
    // This raw-FFI smoke test is therefore ignored by default. Run it with
    // `cargo test -- --ignored` on a kernel that exposes the KPP interface.
    #[test]
    #[ignore]
    fn test_kpp_ecdh() {
        let alg = CString::new("ecdh").expect("Unable to create CString");
        let access = KCAPI_ACCESS_HEURISTIC as i32;

        unsafe {
            // Alice
            let mut alice =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;
            assert_eq!(kcapi_kpp_init(&mut alice as *mut _, alg.as_ptr(), 0), 0);
            assert_eq!(
                kcapi_kpp_ecdh_setcurve(alice, ECC_CURVE_NIST_P256 as ::std::os::raw::c_ulong),
                0
            );
            let outsize = kcapi_kpp_setkey(alice, std::ptr::null(), 0);
            assert!(outsize > 0);
            let mut alice_pub = vec![0u8; outsize as usize];
            let alice_publen = kcapi_kpp_keygen(
                alice,
                alice_pub.as_mut_ptr(),
                alice_pub.len() as u64,
                access,
            );
            assert!(alice_publen > 0);

            // Bob
            let mut bob =
                Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] })) as *mut kcapi_handle;
            assert_eq!(kcapi_kpp_init(&mut bob as *mut _, alg.as_ptr(), 0), 0);
            assert_eq!(
                kcapi_kpp_ecdh_setcurve(bob, ECC_CURVE_NIST_P256 as ::std::os::raw::c_ulong),
                0
            );
            assert!(kcapi_kpp_setkey(bob, std::ptr::null(), 0) > 0);
            let mut bob_pub = vec![0u8; outsize as usize];
            let bob_publen =
                kcapi_kpp_keygen(bob, bob_pub.as_mut_ptr(), bob_pub.len() as u64, access);
            assert!(bob_publen > 0);

            // Shared secrets must match
            let mut alice_ss = vec![0u8; outsize as usize];
            let alice_sslen = kcapi_kpp_ssgen(
                alice,
                bob_pub.as_ptr(),
                bob_publen as u64,
                alice_ss.as_mut_ptr(),
                alice_ss.len() as u64,
                access,
            );
            assert!(alice_sslen > 0);

            let mut bob_ss = vec![0u8; outsize as usize];
            let bob_sslen = kcapi_kpp_ssgen(
                bob,
                alice_pub.as_ptr(),
                alice_publen as u64,
                bob_ss.as_mut_ptr(),
                bob_ss.len() as u64,
                access,
            );
            assert!(bob_sslen > 0);

            assert_eq!(
                alice_ss[..alice_sslen as usize],
                bob_ss[..bob_sslen as usize]
            );

            kcapi_kpp_destroy(alice);
            kcapi_kpp_destroy(bob);
        }
    }
}
