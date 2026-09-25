//! zlib (RFC 1950): 2-byte header, raw deflate body, big-endian Adler-32 of the output.

use super::deflate::probe_block_header;
use crate::checksum::adler32;
use crate::codec::{Codec, CompressionParams, DecodeCtx, DecodeError, Decoded, Format};

pub struct ZlibCodec;

const HEADER_LEN: usize = 2;
const TRAILER_LEN: usize = 4;

/// If `data` starts with a valid zlib header, return its window bits (8..=15).
/// Streams that need a preset dictionary (FDICT) are rejected because they can't be decoded.
pub fn parse_header(data: &[u8]) -> Option<u8> {
    let &[cmf, flg, ..] = data else { return None };
    let cinfo = cmf >> 4;
    let valid = cmf & 0x0f == 8
        && cinfo <= 7
        && ((u16::from(cmf) << 8) | u16::from(flg)) % 31 == 0
        && flg & 0x20 == 0;
    valid.then_some(cinfo + 8)
}

impl Codec for ZlibCodec {
    fn format(&self) -> Format {
        Format::Zlib
    }

    fn self_verifying(&self) -> bool {
        true
    }

    fn probe(&self, data: &[u8]) -> bool {
        parse_header(data).is_some() && probe_block_header(&data[HEADER_LEN..])
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let window_bits = parse_header(data).ok_or(DecodeError::BadHeader)?;
        let (consumed, len) = ctx.inflate(&data[HEADER_LEN..])?;
        let end = HEADER_LEN + consumed;
        let trailer = data.get(end..end + TRAILER_LEN).ok_or(DecodeError::Truncated)?;
        let stored = u32::from_be_bytes(trailer.try_into().unwrap());
        if adler32(ctx.output(len)) != stored {
            return Err(DecodeError::ChecksumMismatch);
        }
        Ok(Decoded {
            compressed_size: end + TRAILER_LEN,
            data: ctx.take_output(len),
            params: CompressionParams { window_bits: Some(window_bits), ..Default::default() },
            original_name: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_validation() {
        assert_eq!(parse_header(&[0x78, 0x9c]), Some(15));
        assert_eq!(parse_header(&[0x78, 0x01]), Some(15));
        assert_eq!(parse_header(&[0x78, 0xda]), Some(15));
        assert_eq!(parse_header(&[0x48, 0x89]), Some(12));
        assert_eq!(parse_header(&[0x78, 0x9d]), None, "bad FCHECK");
        assert_eq!(parse_header(&[0x78, 0xbb]), None, "FDICT set");
        assert_eq!(parse_header(&[0x88, 0x98]), None, "CINFO > 7");
        assert_eq!(parse_header(&[0x78]), None);
    }

    #[test]
    fn decode_and_checksum() {
        // zlib.compress(b"hello", 6) with a stored-free fixed block
        let stream = [0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15];
        let mut ctx = DecodeCtx::new(1 << 20);
        let d = ZlibCodec.decode(&stream, &mut ctx).unwrap();
        assert_eq!(d.data, b"hello");
        assert_eq!(d.compressed_size, stream.len());
        assert_eq!(d.params.window_bits, Some(15));

        let mut bad = stream;
        bad[12] ^= 1;
        assert_eq!(ZlibCodec.decode(&bad, &mut ctx).unwrap_err(), DecodeError::ChecksumMismatch);
        assert_eq!(ZlibCodec.decode(&stream[..11], &mut ctx).unwrap_err(), DecodeError::Truncated);
    }
}
