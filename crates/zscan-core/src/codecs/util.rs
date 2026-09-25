//! Small helpers shared by the codecs.

use crate::codec::DecodeError;
use crate::params::EncoderParams;

pub(crate) const INITIAL_OUTPUT: usize = 64 * 1024;

/// Make room in `out` for more decoder output, doubling up to `max` bytes.
pub(crate) fn grow(out: &mut Vec<u8>, max: usize) -> Result<(), DecodeError> {
    if out.len() >= max {
        return Err(DecodeError::TooLarge(max));
    }
    let extra = out.len().max(INITIAL_OUTPUT).min(max - out.len());
    out.reserve_exact(extra);
    Ok(())
}

/// A starting output buffer: `hint` bytes (e.g. a size from the header) if known and
/// sane, else a small default, never above `max`.
pub(crate) fn output_buffer(hint: Option<u64>, max: usize) -> Vec<u8> {
    let cap = hint.and_then(|h| usize::try_from(h).ok()).unwrap_or(INITIAL_OUTPUT).clamp(1, max.max(1));
    Vec::with_capacity(cap.min(64 << 20))
}

pub(crate) fn wrong_encoder(expected: &str, got: &EncoderParams) -> String {
    format!("{got} are not {expected} settings")
}
