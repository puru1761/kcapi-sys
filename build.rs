use std::env;
use std::path::PathBuf;

const LIB: &str = "kcapi";

fn main() {
    println!("cargo:rustc-link-lib={}", LIB);
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect(format!("unable to generate bindings for lib{}", LIB).as_str());

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write libkcapi bindings");
}
