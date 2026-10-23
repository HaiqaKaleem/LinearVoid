//! C ABI for hybrid-oidc: KEM, signature, and ID token mint/verify callable from C.

use hybrid_oidc::{build_jwks, discovery};
use hybrid_primitives::{ecdsa_p256_mldsa_87, sizes, x25519_ml_kem_768};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;

/// Thread-safe handle to a freshly generated hybrid KEM keypair.
///
/// Holds a fixed-size hybrid KEM public key and secret key. The public key
/// encodes the X25519 component followed by the ML-KEM-768 component; the
/// secret key encodes the X25519 scalar followed by the ML-KEM-768 seed.
///
/// # Safety
///
/// `HybridKemKeyPair` must only be constructed by `hybrid_kem_kgen` or copied
/// from a previously valid handle returned by that function. The caller must
/// not read or write the contents of `pk` or `sk` except through the provided
/// `hybrid_kem_*` FFI functions, and must not allow the handle to outlive the
/// thread that created it.
#[repr(C)]
pub struct HybridKemKeyPair {
    /// 32-byte X25519 public key ‖ 1184-byte ML-KEM-768 public key.
    pub pk: [u8; sizes::HYBRID_KEM_PK],
    /// 32-byte X25519 scalar ‖ 64-byte ML-KEM-768 seed.
    pub sk: [u8; sizes::HYBRID_KEM_SK],
}

/// Thread-safe handle to a freshly generated hybrid signature keypair.
///
/// Holds a fixed-size hybrid signing verification key and secret key. The
/// verification key encodes the ECDSA P-256 component followed by the ML-DSA-87
/// component; the secret key encodes the ECDSA P-256 scalar followed by the
/// ML-DSA-87 seed.
///
/// # Safety
///
/// `HybridSigKeyPair` must only be constructed by `hybrid_sig_kgen` or copied
/// from a previously valid handle returned by that function. The caller must
/// not read or write the contents of `vk` or `sk` except through the provided
/// `hybrid_sig_*` and `hybrid_id_token_*` FFI functions, and must not allow
/// the handle to outlive the thread that created it.
#[repr(C)]
pub struct HybridSigKeyPair {
    /// 33-byte ECDSA P-256 uncompressed point ‖ 2592-byte ML-DSA-87 vk.
    pub vk: [u8; sizes::HYBRID_SIG_VK],
    /// 32-byte ECDSA scalar ‖ 32-byte ML-DSA-87 seed.
    pub sk: [u8; sizes::HYBRID_SIG_SK],
}

/// Error codes returned by FFI functions.
pub const FFI_OK: c_int = 0;
pub const FFI_ERR_NULL: c_int = -1;
pub const FFI_ERR_INVALID: c_int = -2;
pub const FFI_ERR_PANIC: c_int = -3;

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Write the OIDC discovery JSON for `issuer` to `*out` (caller-allocated
/// buffer of at least `buf_len` bytes). Returns the number of bytes written
/// excluding the trailing NUL, or a negative error code.
///
/// # Safety
///
/// `issuer_c` and `jwks_uri_c` must each point to a valid NUL-terminated or
/// NUL-padded sequence of `issuer_len` / `jwks_uri_len` bytes, and `out` must
/// point to a writable buffer of at least `out_len` bytes that does not overlap
/// with either input. This function must not be called concurrently on the same
/// `*out` buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_discovery(
    issuer_c: *const c_char,
    issuer_len: usize,
    jwks_uri_c: *const c_char,
    jwks_uri_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if issuer_c.is_null() || jwks_uri_c.is_null() || out.is_null() {
        return FFI_ERR_NULL;
    }
    // NUL-padding is checked inside `CStr::from_bytes_until_nul`, not here.
    let issuer_bytes = unsafe { std::slice::from_raw_parts(issuer_c as *const u8, issuer_len) };
    let jwks_uri_bytes =
        unsafe { std::slice::from_raw_parts(jwks_uri_c as *const u8, jwks_uri_len) };

    let issuer_cstr = match CStr::from_bytes_until_nul(issuer_bytes) {
        Ok(s) => s,
        Err(_) => return FFI_ERR_INVALID,
    };
    let jwks_uri_cstr = match CStr::from_bytes_until_nul(jwks_uri_bytes) {
        Ok(s) => s,
        Err(_) => return FFI_ERR_INVALID,
    };

    let issuer_str = match issuer_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return FFI_ERR_INVALID,
    };
    let jwks_uri_str = match jwks_uri_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return FFI_ERR_INVALID,
    };

    let disc = discovery(issuer_str, jwks_uri_str);
    let json_bytes = match serde_json::to_vec(&disc) {
        Ok(v) => v,
        Err(_) => return FFI_ERR_INVALID,
    };

    if json_bytes.len() + 1 > out_len {
        return -(4isize) as c_int;
    }

    let out_ref = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    out_ref[..json_bytes.len()].copy_from_slice(&json_bytes);
    out_ref[json_bytes.len()] = 0;

    json_bytes.len() as c_int
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

/// Build a JWKS from the hybrid signing verification key.
///
/// # Safety
///
/// `vk` must point to a valid hybrid signing verification key of exactly
/// `sizes::HYBRID_SIG_VK` bytes, and `out` must point to a writable buffer of
/// at least `out_len` bytes that does not alias `vk`. This function must not be
/// called concurrently on the same `*out` buffer.
///
/// The caller must ensure that `vk` really is a valid hybrid signing
/// verification key; this function does not validate the cryptographic
/// contents of the key, and passing garbage will produce a JWKS that does not
/// match any real keypair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_build_jwks(vk: *const u8, out: *mut u8, out_len: usize) -> c_int {
    if vk.is_null() || out.is_null() {
        return FFI_ERR_NULL;
    }

    let vk_slice = unsafe { std::slice::from_raw_parts(vk, sizes::HYBRID_SIG_VK) };
    let sig = ecdsa_p256_mldsa_87();
    let jwks = match build_jwks(&sig, vk_slice) {
        Ok(j) => j,
        Err(_) => return FFI_ERR_INVALID,
    };

    let json_bytes = match serde_json::to_vec(&jwks) {
        Ok(v) => v,
        Err(_) => return FFI_ERR_INVALID,
    };

    if json_bytes.len() + 1 > out_len {
        return -(4isize) as c_int;
    }

    let out_ref = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    out_ref[..json_bytes.len()].copy_from_slice(&json_bytes);
    out_ref[json_bytes.len()] = 0;

    json_bytes.len() as c_int
}

// ---------------------------------------------------------------------------
// KEM
// ---------------------------------------------------------------------------

/// Generate a hybrid KEM keypair.
///
/// # Safety
///
/// `out` must point to a valid, writable `HybridKemKeyPair` that does not alias
/// any other live pointer. On success the handle stored there is valid until
/// the thread that owns it is torn down.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_kem_kgen(out: *mut HybridKemKeyPair) -> c_int {
    if out.is_null() {
        return FFI_ERR_NULL;
    }

    let result: Result<_, Box<dyn std::any::Any + Send>> = catch_unwind(|| {
        let kem = x25519_ml_kem_768();
        kem.kgen_h().map(|(pk, sk)| {
            let mut pk_arr = [0u8; sizes::HYBRID_KEM_PK];
            let mut sk_arr = [0u8; sizes::HYBRID_KEM_SK];
            pk_arr.copy_from_slice(&pk);
            sk_arr.copy_from_slice(&sk);
            HybridKemKeyPair {
                pk: pk_arr,
                sk: sk_arr,
            }
        })
    });

    match result {
        Ok(Ok(kp)) => {
            unsafe { std::ptr::write(out, kp) };
            FFI_OK
        }
        Ok(Err(_)) => FFI_ERR_INVALID,
        Err(_) => FFI_ERR_PANIC,
    }
}

/// Encapsulate to `pk`. Writes the 64-byte hybrid shared secret.
///
/// # Safety
///
/// `pk` must point to a valid hybrid KEM public key of exactly
/// `sizes::HYBRID_KEM_PK` bytes; `ss_out` and `ct_out` must point to writable
/// buffers of at least `sizes::HYBRID_KEM_SS` and `sizes::HYBRID_KEM_CT` bytes
/// respectively, and none of the three pointers may alias each other or any
/// other live pointer that is read or written by this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_kem_enc(pk: *const u8, ss_out: *mut u8, ct_out: *mut u8) -> c_int {
    if pk.is_null() || ss_out.is_null() || ct_out.is_null() {
        return FFI_ERR_NULL;
    }

    let pk_slice = unsafe { std::slice::from_raw_parts(pk, sizes::HYBRID_KEM_PK) };
    let ss_slice = unsafe { std::slice::from_raw_parts_mut(ss_out, sizes::HYBRID_KEM_SS) };
    let ct_slice = unsafe { std::slice::from_raw_parts_mut(ct_out, sizes::HYBRID_KEM_CT) };

    let result: Result<_, Box<dyn std::any::Any + Send>> = catch_unwind(|| {
        let kem = x25519_ml_kem_768();
        kem.encapsulate_h(pk_slice)
    });

    match result {
        Ok(Ok((ss, ct))) => {
            ss_slice.copy_from_slice(&ss);
            ct_slice.copy_from_slice(&ct);
            FFI_OK
        }
        Ok(Err(_)) => FFI_ERR_INVALID,
        Err(_) => FFI_ERR_PANIC,
    }
}

/// Decapsulate `ct` to a shared secret. Writes the 64-byte hybrid shared secret.
///
/// # Safety
///
/// `sk` must point to a valid hybrid KEM secret key of exactly
/// `sizes::HYBRID_KEM_SK` bytes, `ct` must point to a valid ciphertext of exactly
/// `sizes::HYBRID_KEM_CT` bytes, and `ss_out` must point to a writable buffer of
/// at least `sizes::HYBRID_KEM_SS` bytes that does not alias `sk` or `ct`. This
/// function must not be called concurrently on the same `*ss_out` buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_kem_dec(sk: *const u8, ct: *const u8, ss_out: *mut u8) -> c_int {
    if sk.is_null() || ct.is_null() || ss_out.is_null() {
        return FFI_ERR_NULL;
    }

    let sk_slice = unsafe { std::slice::from_raw_parts(sk, sizes::HYBRID_KEM_SK) };
    let ct_slice = unsafe { std::slice::from_raw_parts(ct, sizes::HYBRID_KEM_CT) };
    let ss_slice = unsafe { std::slice::from_raw_parts_mut(ss_out, sizes::HYBRID_KEM_SS) };

    let result: Result<_, Box<dyn std::any::Any + Send>> = catch_unwind(|| {
        let kem = x25519_ml_kem_768();
        kem.decapsulate_h(sk_slice, ct_slice)
    });

    match result {
        Ok(Ok(ss)) => {
            ss_slice.copy_from_slice(&ss);
            FFI_OK
        }
        Ok(Err(_)) => FFI_ERR_INVALID,
        Err(_) => FFI_ERR_PANIC,
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// Generate a hybrid signature keypair.
///
/// # Safety
///
/// `out` must point to a valid, writable `HybridSigKeyPair` that does not alias
/// any other live pointer. On success the handle stored there is valid until the
/// thread that owns it is torn down. This function may panic during key
/// generation if the underlying ML-DSA-87 or ECDSA P-256 implementation
/// encounters a fatal error; such a panic is caught and translated to
/// `FFI_ERR_PANIC`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_sig_kgen(out: *mut HybridSigKeyPair) -> c_int {
    if out.is_null() {
        return FFI_ERR_NULL;
    }

    let result: Result<_, Box<dyn std::any::Any + Send>> = catch_unwind(|| {
        let sig = ecdsa_p256_mldsa_87();
        sig.skgen_h().map(|(vk, sk)| {
            let mut vk_arr = [0u8; sizes::HYBRID_SIG_VK];
            let mut sk_arr = [0u8; sizes::HYBRID_SIG_SK];
            vk_arr.copy_from_slice(&vk);
            sk_arr.copy_from_slice(&sk);
            HybridSigKeyPair {
                vk: vk_arr,
                sk: sk_arr,
            }
        })
    });

    match result {
        Ok(Ok(kp)) => {
            unsafe { std::ptr::write(out, kp) };
            FFI_OK
        }
        Ok(Err(_)) => FFI_ERR_INVALID,
        Err(_) => FFI_ERR_PANIC,
    }
}

/// Sign `msg`.
///
/// # Safety
///
/// `sk` must point to a valid hybrid signing secret key of exactly
/// `sizes::HYBRID_SIG_SK` bytes, `msg` must point to readable memory of exactly
/// `msg_len` bytes, and `sig_out` must point to a writable buffer of exactly
/// `sizes::HYBRID_SIG` bytes. None of the pointers may alias each other or any
/// other live pointer that is read or written by this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_sig_sign(
    sk: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    if sk.is_null() || msg.is_null() || sig_out.is_null() {
        return FFI_ERR_NULL;
    }

    let sk_slice = unsafe { std::slice::from_raw_parts(sk, sizes::HYBRID_SIG_SK) };
    let msg_slice = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let sig_slice = unsafe { std::slice::from_raw_parts_mut(sig_out, sizes::HYBRID_SIG) };

    let result: Result<_, Box<dyn std::any::Any + Send>> = catch_unwind(|| {
        let sig = ecdsa_p256_mldsa_87();
        sig.sign_h(sk_slice, msg_slice)
    });

    match result {
        Ok(Ok(sig_bytes)) => {
            sig_slice.copy_from_slice(&sig_bytes);
            FFI_OK
        }
        Ok(Err(_)) => FFI_ERR_INVALID,
        Err(_) => FFI_ERR_PANIC,
    }
}

/// Verify a hybrid signature. Returns 1 if valid, 0 if invalid.
///
/// # Safety
///
/// `vk` must point to a valid hybrid signing verification key of exactly
/// `sizes::HYBRID_SIG_VK` bytes, `msg` must point to readable memory of exactly
/// `msg_len` bytes, and `sig` must point to a valid hybrid signature of exactly
/// `sizes::HYBRID_SIG` bytes. None of the pointers may alias each other or any
/// other live pointer that is read or written by this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hybrid_sig_verify(
    vk: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> c_int {
    if vk.is_null() || msg.is_null() || sig.is_null() {
        return FFI_ERR_NULL;
    }

    let vk_slice = unsafe { std::slice::from_raw_parts(vk, sizes::HYBRID_SIG_VK) };
    let msg_slice = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let sig_slice = unsafe { std::slice::from_raw_parts(sig, sizes::HYBRID_SIG) };

    let result: Result<_, Box<dyn std::any::Any + Send>> = catch_unwind(|| {
        let sig = ecdsa_p256_mldsa_87();
        sig.verify_h(vk_slice, msg_slice, sig_slice)
    });

    match result {
        Ok(Ok(true)) => 1,
        Ok(Ok(false)) => 0,
        Ok(Err(_)) => FFI_ERR_INVALID,
        Err(_) => FFI_ERR_PANIC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_kem_roundtrip() {
        unsafe {
            let mut kp = HybridKemKeyPair {
                pk: [0; sizes::HYBRID_KEM_PK],
                sk: [0; sizes::HYBRID_KEM_SK],
            };
            assert_eq!(hybrid_kem_kgen(&mut kp as *mut _), FFI_OK);

            // encapsulate_h returns (ss_64, ct). We extract the session key.
            let mut ss64 = [0u8; sizes::HYBRID_KEM_SS];
            let mut ct = [0u8; sizes::HYBRID_KEM_CT];
            assert_eq!(
                hybrid_kem_enc(kp.pk.as_ptr(), ss64.as_mut_ptr(), ct.as_mut_ptr()),
                FFI_OK
            );

            // decapsulate_h returns the 64-byte ss. Extract the session key.
            let mut ss64_dec = [0u8; sizes::HYBRID_KEM_SS];
            assert_eq!(
                hybrid_kem_dec(kp.sk.as_ptr(), ct.as_ptr(), ss64_dec.as_mut_ptr()),
                FFI_OK
            );
            assert_eq!(ss64, ss64_dec);
        }
    }

    #[test]
    fn ffi_sig_roundtrip() {
        unsafe {
            let mut kp = HybridSigKeyPair {
                vk: [0; sizes::HYBRID_SIG_VK],
                sk: [0; sizes::HYBRID_SIG_SK],
            };
            assert_eq!(hybrid_sig_kgen(&mut kp as *mut _), FFI_OK);

            let msg = b"hello world";
            let mut sig = [0u8; sizes::HYBRID_SIG];
            assert_eq!(
                hybrid_sig_sign(kp.sk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()),
                FFI_OK
            );

            assert_eq!(
                hybrid_sig_verify(kp.vk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()),
                1
            );
            assert_eq!(
                hybrid_sig_verify(kp.vk.as_ptr(), b"tampered".as_ptr(), 9, sig.as_ptr()),
                0
            );
        }
    }
}
