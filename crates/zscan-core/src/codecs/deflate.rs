//! Raw deflate (RFC 1951).

use crate::codec::{Codec, CompressionParams, DecodeCtx, DecodeError, Decoded, Format};

pub struct DeflateCodec;

/// Cheap check that `data` starts with a plausible deflate block header.
///
/// - BTYPE 11 is reserved, so it is rejected.
/// - Stored blocks need LEN == !NLEN. The header's 5 padding bits must also be zero;
///   the spec does not require that, but every real encoder writes zeros.
/// - Dynamic blocks need HLIT <= 29, HDIST <= 29, and a code-length code that is a
///   complete prefix code. zlib's inflate rejects incomplete ones and its deflate never
///   writes one. This check alone rejects most random offsets before any table building.
pub fn probe_block_header(data: &[u8]) -> bool {
    let Some(&b0) = data.first() else { return false };
    match (b0 >> 1) & 3 {
        0 => {
            b0 >> 3 == 0
                && data.len() >= 5
                && u16::from_le_bytes([data[1], data[2]]) == !u16::from_le_bytes([data[3], data[4]])
        }
        1 => true,
        2 => probe_dynamic_header(data),
        _ => false,
    }
}

fn probe_dynamic_header(data: &[u8]) -> bool {
    // The header fits in 3 + 5 + 5 + 4 + 19 * 3 = 74 bits.
    let mut bytes = [0u8; 16];
    let n = data.len().min(10);
    bytes[..n].copy_from_slice(&data[..n]);
    let bits = u128::from_le_bytes(bytes);
    let field = |pos: u32, width: u32| ((bits >> pos) & ((1 << width) - 1)) as u32;

    let (hlit, hdist, hclen) = (field(3, 5), field(8, 5), field(13, 4) + 4);
    if hlit > 29 || hdist > 29 {
        return false;
    }
    if data.len() < (17 + 3 * hclen as usize).div_ceil(8) {
        return true; // Too short to judge; decode will report truncation.
    }
    // Kraft sum in units of 2^-7 (code lengths are at most 7): complete means exactly 128.
    let kraft: u32 = (0..hclen).map(|i| field(17 + 3 * i, 3)).filter(|&len| len > 0).map(|len| 1 << (7 - len)).sum();
    kraft == 128
}

impl Codec for DeflateCodec {
    fn format(&self) -> Format {
        Format::Deflate
    }

    fn self_verifying(&self) -> bool {
        false
    }

    fn probe(&self, data: &[u8]) -> bool {
        probe_block_header(data)
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let (consumed, len) = ctx.inflate(data)?;
        Ok(Decoded {
            compressed_size: consumed,
            data: ctx.take_output(len),
            params: CompressionParams::default(),
            original_name: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_rejects_reserved_and_bad_stored() {
        assert!(!probe_block_header(&[0b110])); // BTYPE 11
        assert!(!probe_block_header(&[0x01, 0x05, 0x00, 0x00, 0x00])); // LEN != !NLEN
        assert!(probe_block_header(&[0x01, 0x05, 0x00, 0xfa, 0xff])); // stored, LEN 5
        assert!(!probe_block_header(&[0x09, 0x05, 0x00, 0xfa, 0xff])); // non-zero padding
        assert!(!probe_block_header(&[]));
    }

    #[test]
    fn decode_stored_block() {
        let stream = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c', 0xee];
        let mut ctx = DecodeCtx::new(1 << 20);
        let d = DeflateCodec.decode(&stream, &mut ctx).unwrap();
        assert_eq!(d.data, b"abc");
        assert_eq!(d.compressed_size, 8, "trailing byte must not be counted");
    }

    #[test]
    fn truncated_and_too_large() {
        let mut ctx = DecodeCtx::new(1 << 20);
        let stream = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a'];
        assert_eq!(DeflateCodec.decode(&stream, &mut ctx).unwrap_err(), DecodeError::Truncated);

        let mut small = DecodeCtx::new(2);
        let stream = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c'];
        assert_eq!(DeflateCodec.decode(&stream, &mut small).unwrap_err(), DecodeError::TooLarge(2));
    }
}
