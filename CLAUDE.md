# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`kcapi-sys` is the official **low-level** Rust FFI binding for [`libkcapi`](https://github.com/smuellerDD/libkcapi) — a userspace interface to the Linux Kernel Cryptographic API (KCAPI / AF_ALG). It exposes the raw, `unsafe` C API and nothing more; the safe, idiomatic wrapper lives in the separate **`kcapi`** crate (this repo is its git submodule). Do not add safe abstractions here — they belong in `kcapi`.

Because it targets the Linux kernel crypto API, the crate **only builds on Linux**, and its tests only pass on a kernel with the `CONFIG_CRYPTO_USER*` options enabled.

## How the bindings are generated

There is almost no hand-written Rust here. `src/lib.rs` is a thin shell:

```rust
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));   // bindgen output
```

`build.rs` does the real work at build time, and which path it takes depends on the active feature:

- **`vendored-kcapi`** (default) — `build.rs` copies the `libkcapi/` submodule into `OUT_DIR`, builds it from source with the `autotools` crate (`reconf -ivf`, `--enable-lib-asym`, `--enable-lib-kpp`), statically links the resulting `libkcapi`, then runs **bindgen** over `wrapper-vendored.h` (which `#include "kcapi.h"`) to produce `bindings.rs`. The copy-to-`OUT_DIR` step is deliberate: autotools mutates the source tree, which would otherwise break `cargo publish` verification.
- **`local-kcapi`** — skips the source build, links a system-installed `libkcapi` (honoring `LIBKCAPI_DIR`), and runs bindgen over `wrapper-local-kcapi.h` (`#include <kcapi.h>`).

So "regenerate the bindings" = "re-run `cargo build`". There is no checked-in `bindings.rs` to edit; change the wrapper header or `build.rs` bindgen options instead.

### bindgen / build gotchas

- **bindgen must be recent enough for the host glibc.** Old bindgen (≤ 0.53) panics with `"… is not a valid Ident"` on modern glibc headers (anonymous structs like `__atomic_wide_counter`). This crate uses bindgen 0.69.
- **`size_t_is_usize(false)` is set on purpose.** bindgen ≥ 0.66 defaults it to `true`, which stops emitting the `size_t` / `ssize_t` type aliases. Both this crate's tests and the `kcapi` crate refer to `kcapi_sys::size_t`, so the aliases must keep existing — do not drop this option.

## Build, test, lint

```sh
cargo build
cargo test                       # tests live in src/test_*.rs (raw FFI calls)
cargo fmt --all -- --check
cargo clippy -- -D warnings
```

CI (`.github/workflows/main.yml`) gates on build → test → fmt → clippy; match all four.

### Submodule (critical)

`libkcapi/` is a nested git submodule and is **empty on a plain clone** — the `vendored-kcapi` build fails until it is checked out:

```sh
git submodule update --init --recursive   # or clone with --recurse-submodules
```

### Native build prerequisites

- Autotools: `autoconf`, `automake`, `libtool` (libkcapi's `configure.ac` uses `LT_INIT`), plus a C toolchain (`build-essential`).
- bindgen: `llvm-dev` **and** `libclang-dev` — `llvm-dev` alone only ships `libclang-cpp.so`; bindgen needs the C-API `libclang.so`.
- If bindgen can't find libclang: `export LLVM_CONFIG_PATH=/usr/bin/llvm-config` (or set `LIBCLANG_PATH`).

Debian/Ubuntu: `sudo apt-get install -y autoconf automake libtool build-essential llvm-dev libclang-dev`

## Cargo features

- `vendored-kcapi` (default) — build & statically link libkcapi from the `libkcapi/` submodule.
- `local-kcapi` — link a system-installed libkcapi instead. Mutually exclusive in practice with the vendored path; the two select different wrapper headers and `build.rs` branches. The `src/test_*.rs` modules are `#[cfg(feature = "vendored-kcapi")]`, so they compile out under `local-kcapi`.

## Tests

`src/test_*.rs` (one per capability: `aead`, `akcipher`, `kdf`, `md`, `rng`, `skcipher`) call the generated `unsafe extern` functions directly — they double as smoke tests for the bindings and as executable usage examples of the raw API. They allocate a `kcapi_handle`, drive an operation, and assert on kernel return codes.

Because they hit real kernel sockets, tests are sensitive to the running kernel's registered algorithms (`/proc/crypto`). When a test fails with `-ENOENT (-2)`, the algorithm name is missing/renamed on this kernel, not a binding bug — prefer algorithm names that current kernels still register (e.g. `drbg_nopr_sha256`, not the long-removed `drbg_nopr_sha1`).

Some algorithms are simply absent on common CI runners — notably `gcm(aes)`/`ccm(aes)` on GitHub-hosted runners (no `algif_aead`/`gcm`), where `kcapi_aead_init` returns `-ENOENT`. For those, skip rather than fail: right after the `init` call, `if ret == -(libc::ENOENT as i64) { return; }` (a `libc` dev-dependency provides the named constant; `ret` is `i64`, hence the `c_int` cast). Skip only on that specific code — don't broaden to "any negative", which would hide real binding regressions.

## Relationship to `kcapi`

This crate is consumed by `kcapi` as a path+submodule dependency. A change here that alters the generated surface (new wrapper symbols, bindgen options, a libkcapi pointer bump) usually requires a matching commit in the parent `kcapi` repo to advance the submodule pointer. Keep the FFI surface faithful to libkcapi; put ergonomics in `kcapi`.
