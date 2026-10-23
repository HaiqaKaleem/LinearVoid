//! Fixed-length encoding helpers (§2 of the spec).
//!
//! The composite schemes build `pkH = pk_c ‖ pk_p` and friends. Every split
//! goes through these helpers so a wrong-sized input produces a typed
//! [`Error`] instead of a panic or, worse, a silent slice past a component
//! boundary.

use crate::error::{Error, Result};

/// Concatenate two byte slices into a fresh vector.
pub fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// Split `buf` at `mid`, validating the *total* length first.
///
/// This is the only sanctioned way the composite layer takes a hybrid
/// encoding apart.
pub fn split_at_checked(buf: &[u8], mid: usize, expected_total: usize) -> Result<(&[u8], &[u8])> {
    if buf.len() != expected_total || mid > buf.len() {
        return Err(Error::InvalidHybridEncoding);
    }
    Ok(buf.split_at(mid))
}

/// Validate an input against an expected length, returning a typed error.
pub fn check_len(buf: &[u8], want: usize, err: Error) -> Result<()> {
    if buf.len() != want {
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_rejects_wrong_total_length() {
        assert!(split_at_checked(&[0u8; 5], 2, 5).is_ok());
        assert_eq!(
            split_at_checked(&[0u8; 4], 2, 5),
            Err(Error::InvalidHybridEncoding)
        );
        assert_eq!(
            split_at_checked(&[0u8; 5], 6, 5),
            Err(Error::InvalidHybridEncoding)
        );
    }
}
