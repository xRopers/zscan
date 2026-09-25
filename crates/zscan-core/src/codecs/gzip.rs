//! gzip (RFC 1952): header with optional fields, raw deflate body,
//! little-endian CRC-32 and ISIZE (size mod 2^32) trailer. Each member is its own stream.

use crate::checksum::crc32;
use crate::codec::{Codec, CompressionParams, DecodeCtx, DecodeError, Decoded, Format};

pub struct GzipCodec;

const MAGIC: [u8; 3] = [0x1f, 0x8b, 0x08];
const FIXED_HEADER_LEN: usize = 10;
const TRAILER_LEN: usize = 8;
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
const FRESERVED: u8 = 0xe0;
/// Longest FNAME/FCOMMENT we accept, so a fake header can't make us search to the end of the file.
const MAX_CSTR: usize = 64 * 1024;

pub struct GzipHeader {
    pub len: usize,
    pub name: Option<String>,
}

pub fn parse_header(data: &[u8]) -> Result<GzipHeader, DecodeError> {
    if !data.starts_with(&MAGIC) {
        return Err(DecodeError::BadHeader);
    }
    let flg = *data.get(3).ok_or(DecodeError::Truncated)?;
    if flg & FRESERVED != 0 {
        return Err(DecodeError::BadHeader);
    }
    if data.len() < FIXED_HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    let mut pos = FIXED_HEADER_LEN;
    if flg & FEXTRA != 0 {
        let xlen = data.get(pos..pos + 2).ok_or(DecodeError::Truncated)?;
        pos += 2 + usize::from(u16::from_le_bytes([xlen[0], xlen[1]]));
    }
    let mut name = None;
    if flg & FNAME != 0 {
        let (bytes, next) = read_cstr(data, pos)?;
        // RFC 1952 says ISO 8859-1, which maps byte-for-byte onto the first 256 code points.
        name = Some(bytes.iter().map(|&b| char::from(b)).collect());
        pos = next;
    }
    if flg & FCOMMENT != 0 {
        pos = read_cstr(data, pos)?.1;
    }
    if flg & FHCRC != 0 {
        let stored = data.get(pos..pos + 2).ok_or(DecodeError::Truncated)?;
        if crc32(&data[..pos]) as u16 != u16::from_le_bytes([stored[0], stored[1]]) {
            return Err(DecodeError::BadHeader);
        }
        pos += 2;
    }
    if pos > data.len() {
        return Err(DecodeError::Truncated);
    }
    Ok(GzipHeader { len: pos, name })
}

/// Returns the bytes before the NUL at or after `pos`, and the index just past the NUL.
fn read_cstr(data: &[u8], pos: usize) -> Result<(&[u8], usize), DecodeError> {
    let rest = data.get(pos..).ok_or(DecodeError::Truncated)?;
    let limit = rest.len().min(MAX_CSTR);
    match rest[..limit].iter().position(|&b| b == 0) {
        Some(n) => Ok((&rest[..n], pos + n + 1)),
        None if limit == MAX_CSTR => Err(DecodeError::BadHeader),
        None => Err(DecodeError::Truncated),
    }
}

impl Codec for GzipCodec {
    fn format(&self) -> Format {
        Format::Gzip
    }

    fn self_verifying(&self) -> bool {
        true
    }

    fn probe(&self, data: &[u8]) -> bool {
        data.len() >= FIXED_HEADER_LEN && data.starts_with(&MAGIC) && data[3] & FRESERVED == 0
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let header = parse_header(data)?;
        let (consumed, len) = ctx.inflate(&data[header.len..])?;
        let end = header.len + consumed;
        let trailer = data.get(end..end + TRAILER_LEN).ok_or(DecodeError::Truncated)?;
        let crc = u32::from_le_bytes(trailer[..4].try_into().unwrap());
        let isize = u32::from_le_bytes(trailer[4..].try_into().unwrap());
        if crc32(ctx.output(len)) != crc || len as u32 != isize {
            return Err(DecodeError::ChecksumMismatch);
        }
        Ok(Decoded {
            compressed_size: end + TRAILER_LEN,
            body: header.len..end,
            data: ctx.take_output(len),
            params: CompressionParams::default(),
            original_name: header.name,
        })
    }

    fn wrap(&self, header: &[u8], body: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(header.len() + body.len() + TRAILER_LEN);
        out.extend_from_slice(header);
        out.extend_from_slice(body);
        out.extend_from_slice(&crc32(data).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_rejects_reserved_flags() {
        let mut h = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff];
        assert!(parse_header(&h).is_ok());
        h[3] = 0x20;
        assert_eq!(parse_header(&h).err(), Some(DecodeError::BadHeader));
    }

    #[test]
    fn header_crc_is_checked() {
        let mut h = vec![0x1f, 0x8b, 0x08, FHCRC, 0, 0, 0, 0, 0, 0xff];
        let crc = crc32(&h) as u16;
        h.extend(crc.to_le_bytes());
        assert_eq!(parse_header(&h).unwrap().len, 12);
        h[11] ^= 1;
        assert_eq!(parse_header(&h).err(), Some(DecodeError::BadHeader));
    }

    #[test]
    fn unterminated_name_is_truncated() {
        let h = [0x1f, 0x8b, 0x08, FNAME, 0, 0, 0, 0, 0, 0xff, b'a', b'b'];
        assert_eq!(parse_header(&h).err(), Some(DecodeError::Truncated));
    }
}
