//! Thin safe wrappers over the libsodium ed25519 group operations used by
//! stealth addressing and FMD. These are the exact primitives `drift.crypto`
//! reaches through PyNaCl (`nacl.bindings`), so binding the same C library keeps
//! the group math byte-identical across implementations — the iron rule, honoured
//! by *composing* libsodium rather than reimplementing curve arithmetic.

use std::sync::Once;

use libsodium_sys as sodium;

static INIT: Once = Once::new();

/// Initialise libsodium once. The core ed25519 ops here are deterministic and do
/// not need the CSPRNG, but `sodium_init` is the documented precondition.
pub fn init() {
    INIT.call_once(|| unsafe {
        // Returns 0 on first init, 1 if already initialised; both are fine.
        assert!(sodium::sodium_init() >= 0, "libsodium failed to initialise");
    });
}

/// Elligator map: 32 uniform bytes → a valid ed25519 point (`from_uniform`).
pub fn ed25519_from_uniform(seed: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    unsafe {
        sodium::crypto_core_ed25519_from_uniform(out.as_mut_ptr(), seed.as_ptr());
    }
    out
}

/// Reduce 64 bytes to a scalar mod L (`crypto_core_ed25519_scalar_reduce`).
pub fn scalar_reduce(wide: &[u8; 64]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    unsafe {
        sodium::crypto_core_ed25519_scalar_reduce(out.as_mut_ptr(), wide.as_ptr());
    }
    out
}

/// Base-point scalar mult, no clamping (`..._base_noclamp`). Errors only if the
/// scalar is zero (libsodium returns -1), which our callers never pass.
pub fn base_mul_noclamp(scalar: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    let rc = unsafe {
        sodium::crypto_scalarmult_ed25519_base_noclamp(out.as_mut_ptr(), scalar.as_ptr())
    };
    assert_eq!(rc, 0, "base_mul_noclamp: zero scalar");
    out
}

/// Point scalar mult, no clamping (`crypto_scalarmult_ed25519_noclamp`).
pub fn point_mul_noclamp(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    init();
    let mut out = [0u8; 32];
    let rc = unsafe {
        sodium::crypto_scalarmult_ed25519_noclamp(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr())
    };
    if rc == 0 {
        Some(out)
    } else {
        None
    }
}

/// Point addition (`crypto_core_ed25519_add`).
pub fn point_add(p: &[u8; 32], q: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    let rc = unsafe { sodium::crypto_core_ed25519_add(out.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
    assert_eq!(rc, 0, "point_add: invalid point");
    out
}

/// Scalar multiply mod L (`crypto_core_ed25519_scalar_mul`).
pub fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    unsafe {
        sodium::crypto_core_ed25519_scalar_mul(out.as_mut_ptr(), a.as_ptr(), b.as_ptr());
    }
    out
}

/// Scalar subtract mod L (`crypto_core_ed25519_scalar_sub`).
pub fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    unsafe {
        sodium::crypto_core_ed25519_scalar_sub(out.as_mut_ptr(), a.as_ptr(), b.as_ptr());
    }
    out
}

/// Scalar inverse mod L (`crypto_core_ed25519_scalar_invert`).
pub fn scalar_invert(a: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    let rc = unsafe { sodium::crypto_core_ed25519_scalar_invert(out.as_mut_ptr(), a.as_ptr()) };
    assert_eq!(rc, 0, "scalar_invert: non-invertible scalar");
    out
}
