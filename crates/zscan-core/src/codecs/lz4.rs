//! LZ4 frames: magic 04 22 4D 18, a descriptor protected by a header checksum, blocks
//! (each optionally checksummed), an end mark, and an optional XXH32 of the content.
//!
//! Encoding uses lz4_flex, which has a single compression level. Frames it made match
//! exactly; frames from the reference `lz4` tool decode and repack but don't match.

use std::io::Write;

use lz4_flex::block::{decompress_into, decompress_into_with_dict};
use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
use xxhash_rust::xxh32::xxh32;

use super::util::wrong_encoder;
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format};
use crate::params::{EncoderParams, Lz4Params};

pub struct Lz4Codec;

const MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];
/// Linked blocks may reference this much of the previous blocks' output.
const LINK_WINDOW: usize = 64 * 1024;

struct Header {
    len: usize,
    block_max: usize,
    independent: bool,
    block_checksums: bool,
    content_checksum: bool,
    content_size: Option<u64>,
}

fn parse_header(data: &[u8]) -> Result<Header, DecodeError> {
    if !data.starts_with(&MAGIC) {
        return Err(DecodeError::BadHeader);
    }
    let (&flg, &bd) = (data.get(4).ok_or(DecodeError::Truncated)?, data.get(5).ok_or(DecodeError::Truncated)?);
    // Version 01, reserved bits clear, no dictionary, block size code 4-7.
    let size_code = (bd >> 4) & 0x07;
    if flg >> 6 != 1 || flg & 0x03 != 0 || bd & 0x8f != 0 || size_code < 4 {
        return Err(DecodeError::BadHeader);
    }
    let mut len = 6;
    let content_size = if flg & 0x08 != 0 {
        let bytes = data.get(len..len + 8).ok_or(DecodeError::Truncated)?;
        len += 8;
        Some(u64::from_le_bytes(bytes.try_into().unwrap()))
    } else {
        None
    };
    let hc = *data.get(len).ok_or(DecodeError::Truncated)?;
    if (xxh32(&data[4..len], 0) >> 8) as u8 != hc {
        return Err(DecodeError::BadHeader);
    }
    Ok(Header {
        len: len + 1,
        block_max: 1 << (2 * u32::from(size_code) + 8),
        independent: flg & 0x20 != 0,
        block_checksums: flg & 0x10 != 0,
        content_checksum: flg & 0x04 != 0,
        content_size,
    })
}

fn params(p: &EncoderParams) -> &Lz4Params {
    match p {
        EncoderParams::Lz4(p) => p,
        other => panic!("{}", wrong_encoder("lz4", other)),
    }
}

fn block_size(bytes: u32) -> Option<BlockSize> {
    match bytes {
        0x1_0000 => Some(BlockSize::Max64KB),
        0x4_0000 => Some(BlockSize::Max256KB),
        0x10_0000 => Some(BlockSize::Max1MB),
        0x40_0000 => Some(BlockSize::Max4MB),
        _ => None,
    }
}

fn read_u32(data: &[u8], pos: usize) -> Result<u32, DecodeError> {
    let bytes = data.get(pos..pos + 4).ok_or(DecodeError::Truncated)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

impl Codec for Lz4Codec {
    fn format(&self) -> Format {
        Format::Lz4
    }

    fn self_verifying(&self) -> bool {
        true
    }

    fn probe(&self, data: &[u8]) -> bool {
        data.len() >= 11 && parse_header(data).is_ok()
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let header = parse_header(data)?;
        let max = ctx.max_output();
        if header.content_size.is_some_and(|n| n > max as u64) {
            return Err(DecodeError::TooLarge(max));
        }
        let mut pos = header.len;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let word = read_u32(data, pos)?;
            pos += 4;
            if word == 0 {
                break; // end mark
            }
            let stored = word & 0x8000_0000 != 0;
            let len = (word & 0x7fff_ffff) as usize;
            if len > header.block_max {
                return Err(DecodeError::InvalidData);
            }
            let block = data.get(pos..pos + len).ok_or(DecodeError::Truncated)?;
            pos += len;
            if header.block_checksums {
                if read_u32(data, pos)? != xxh32(block, 0) {
                    return Err(DecodeError::ChecksumMismatch);
                }
                pos += 4;
            }
            let start = out.len();
            if stored {
                out.extend_from_slice(block);
            } else {
                out.resize(start + header.block_max, 0);
                let n = if header.independent {
                    decompress_into(block, &mut out[start..])
                } else {
                    let (prev, rest) = out.split_at_mut(start);
                    decompress_into_with_dict(block, rest, &prev[prev.len().saturating_sub(LINK_WINDOW)..])
                }
                .map_err(|_| DecodeError::InvalidData)?;
                out.truncate(start + n);
            }
            if out.len() > max {
                return Err(DecodeError::TooLarge(max));
            }
        }
        if header.content_checksum {
            if read_u32(data, pos)? != xxh32(&out, 0) {
                return Err(DecodeError::ChecksumMismatch);
            }
            pos += 4;
        }
        if header.content_size.is_some_and(|n| n != out.len() as u64) {
            return Err(DecodeError::InvalidData);
        }
        Ok(Decoded { compressed_size: pos, body: 0..pos, data: out, original_name: None })
    }

    /// lz4_flex has no levels, so the header flags are the only settings to try.
    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        let p = self.default_params(stream, decoded);
        block_size(params(&p).block_size)?;
        self.encode(stream, decoded, &decoded.data, &p).is_ok_and(|s| s == stream).then_some(p)
    }

    fn default_params(&self, stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        let p = match parse_header(stream) {
            Ok(h) => Lz4Params {
                block_size: h.block_max as u32,
                independent_blocks: h.independent,
                block_checksums: h.block_checksums,
                content_checksum: h.content_checksum,
                content_size: h.content_size.is_some(),
            },
            Err(_) => Lz4Params {
                block_size: 0x1_0000,
                independent_blocks: true,
                block_checksums: false,
                content_checksum: true,
                content_size: false,
            },
        };
        EncoderParams::Lz4(p)
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, p: &EncoderParams) -> Result<EncoderParams, String> {
        match p {
            EncoderParams::Lz4(l) if block_size(l.block_size).is_some() => Ok(p.clone()),
            EncoderParams::Lz4(l) => Err(format!("lz4 block size {} is not 64K, 256K, 1M or 4M", l.block_size)),
            other => Err(wrong_encoder("lz4", other)),
        }
    }

    /// Linked blocks let each block reference the previous 64 KiB, which compresses better.
    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        let base = *params(base);
        if base.independent_blocks {
            vec![EncoderParams::Lz4(Lz4Params { independent_blocks: false, ..base })]
        } else {
            vec![]
        }
    }

    fn encode(&self, _stream: &[u8], _decoded: &Decoded, data: &[u8], p: &EncoderParams) -> Result<Vec<u8>, String> {
        let p = params(p);
        let info = FrameInfo::new()
            .block_size(block_size(p.block_size).expect("lz4 block size"))
            .block_mode(if p.independent_blocks { BlockMode::Independent } else { BlockMode::Linked })
            .block_checksums(p.block_checksums)
            .content_checksum(p.content_checksum)
            .content_size(p.content_size.then_some(data.len() as u64));
        let mut encoder = FrameEncoder::with_frame_info(info, Vec::with_capacity(data.len() / 2 + 64));
        encoder.write_all(data).expect("writing to a Vec cannot fail");
        Ok(encoder.finish().expect("lz4 frame finish"))
    }
}
