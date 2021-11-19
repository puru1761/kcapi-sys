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
 * Build instructions for the libkcapi low-level rust bindings
 */
use std::env;
use std::fs;
use std::path::PathBuf;

const LIB: &str = "kcapi";

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let include_path = out_path.join("include");
    let wrapper_h_path = include_path.join("wrapper.h");
    let build_path = out_path.join("libkcapi");

    /*
     * Copy the libkcapi sources to OUT_DIR.
     * We need to do this because the libkcapi sources are modified by automake,
     * and this causes package verification errors on running cargo publish.
     */
    let mut opts = fs_extra::dir::CopyOptions::new();
    opts.copy_inside = true;
    opts.overwrite = true;
    match fs_extra::dir::copy("libkcapi", out_path.clone(), &opts) {
        Ok(_ret) => {}
        Err(e) => panic!("Failed to copy libkcapi to {}: {}", build_path.display(), e),
    };

    let dst = autotools::Config::new(build_path)
        .reconf("-ivf")
        .enable("lib-asym", None)
        .enable("lib-kpp", None)
        .disable("dependency-tracking", None)
        .cflag("-O")
        .build();

    /*
     * FIXME: Need to copy wrapper.h to OUT_DIR in order to make the
     * wrappings compile. This is a hack for now until a more standard way
     * is found to do this.
     */
    match fs::copy("wrapper.h", wrapper_h_path.clone()) {
        Ok(_ok) => {}
        Err(e) => {
            panic!(
                "Unable to copy wrapper.h to {}: {}",
                wrapper_h_path.display(),
                e
            );
        }
    }

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib={}", LIB);
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header(format!("{}", wrapper_h_path.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .unwrap_or_else(|_| panic!("unable to generate bindings for lib{}", LIB));

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write libkcapi bindings");
}
