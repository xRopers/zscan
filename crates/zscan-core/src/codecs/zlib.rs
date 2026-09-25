//! zlib (RFC 1950): 2-byte header, raw deflate body, big-endian Adler-32 of the output.

use super::deflate::probe_block_header;
use crate::checksum::adler32;
use super::deflate::{adapt_family_params, family_params, find_family_params, stronger_family_params};
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format};
use crate::deflater::{DeflateParams, compress_raw};
use crate::params::EncoderParams;

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
        parse_header(data).ok_or(DecodeError::BadHeader)?;
        let (consumed, len) = ctx.inflate(&data[HEADER_LEN..])?;
        let end = HEADER_LEN + consumed;
        let trailer = data.get(end..end + TRAILER_LEN).ok_or(DecodeError::Truncated)?;
        let stored = u32::from_be_bytes(trailer.try_into().unwrap());
        if adler32(ctx.output(len)) != stored {
            return Err(DecodeError::ChecksumMismatch);
        }
        Ok(Decoded { compressed_size: end + TRAILER_LEN, body: HEADER_LEN..end, data: ctx.take_output(len), original_name: None })
    }

    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        find_family_params(stream, decoded, parse_header(stream))
    }

    fn default_params(&self, stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        EncoderParams::Deflate(DeflateParams::zlib_default(header_window(stream)))
    }

    fn adapt_params(&self, stream: &[u8], _decoded: &Decoded, params: &EncoderParams) -> Result<EncoderParams, String> {
        // The header declares the largest window a decoder must provide; never exceed it.
        adapt_family_params(params, header_window(stream))
    }

    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        stronger_family_params(base)
    }

    /// Reuses the original 2-byte header and appends a fresh Adler-32.
    fn encode(&self, stream: &[u8], decoded: &Decoded, data: &[u8], params: &EncoderParams) -> Vec<u8> {
        let body = compress_raw(data, family_params(params));
        let mut out = Vec::with_capacity(HEADER_LEN + body.len() + TRAILER_LEN);
        out.extend_from_slice(&stream[..decoded.body.start]);
        out.extend_from_slice(&body);
        out.extend_from_slice(&adler32(data).to_be_bytes());
        out
    }
}

/// Window bits declared by a zlib header, clamped to what zlib can encode with (9..=15).
fn header_window(stream: &[u8]) -> u8 {
    parse_header(stream).unwrap_or(15).max(9)
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
        // Made by zlib at its defaults, so the search finds them and encode rebuilds it.
        let found = ZlibCodec.find_params(&stream, &d).unwrap();
        assert_eq!(found, EncoderParams::Deflate(DeflateParams::zlib_default(15)));
        assert_eq!(ZlibCodec.encode(&stream, &d, b"hello", &found), stream);

        let mut bad = stream;
        bad[12] ^= 1;
        assert_eq!(ZlibCodec.decode(&bad, &mut ctx).unwrap_err(), DecodeError::ChecksumMismatch);
        assert_eq!(ZlibCodec.decode(&stream[..11], &mut ctx).unwrap_err(), DecodeError::Truncated);
    }
}
