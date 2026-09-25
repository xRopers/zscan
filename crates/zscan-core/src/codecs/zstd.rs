//! Zstandard frames: magic 28 B5 2F FD, a frame header, blocks, and an optional XXH64
//! content checksum that libzstd verifies. Frames that need a dictionary are rejected.

use zstd::zstd_safe::{CCtx, CParameter, DCtx, InBuffer, OutBuffer, ResetDirective, zstd_sys::ZSTD_EndDirective};

use super::util::{grow, output_buffer, wrong_encoder};
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format};
use crate::params::{EncoderParams, ZstdParams};

pub struct ZstdCodec;

const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Levels to try when matching, most common first. 0 means "default" (3) in libzstd.
const MATCH_LEVELS: [i32; 29] =
    [3, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, -1, -2, -3, -4, -5, -6, -7];

struct FrameFlags {
    checksum: bool,
    content_size: bool,
    has_dict: bool,
}

fn frame_flags(data: &[u8]) -> Option<FrameFlags> {
    if !data.starts_with(&MAGIC) {
        return None;
    }
    let fhd = *data.get(4)?;
    if fhd & 0x08 != 0 {
        return None; // reserved bit
    }
    let single_segment = fhd & 0x20 != 0;
    Some(FrameFlags {
        checksum: fhd & 0x04 != 0,
        content_size: fhd >> 6 != 0 || single_segment,
        has_dict: fhd & 0x03 != 0,
    })
}

fn params(p: &EncoderParams) -> &ZstdParams {
    match p {
        EncoderParams::Zstd(p) => p,
        other => panic!("{}", wrong_encoder("zstd", other)),
    }
}

/// Compress `data` in one pass, handing output to `sink` in small chunks; returns false
/// if `sink` stopped early. Used both to encode and, with a comparing sink, to test
/// candidate settings without producing the whole frame.
fn compress(data: &[u8], p: &ZstdParams, mut sink: impl FnMut(&[u8]) -> bool) -> bool {
    let mut cctx = CCtx::create();
    let set = |cctx: &mut CCtx, param| cctx.set_parameter(param).expect("zstd parameter");
    set(&mut cctx, CParameter::CompressionLevel(p.level));
    set(&mut cctx, CParameter::ChecksumFlag(p.checksum));
    set(&mut cctx, CParameter::ContentSizeFlag(p.content_size));
    // A frame with a content size was made knowing the input size, which also tunes the
    // compression parameters. One without was made by a streaming encoder that didn't
    // know it: feed everything with e_continue first, because an e_end on the first call
    // makes libzstd infer the size.
    let known_size = p.content_size;
    if known_size {
        cctx.set_pledged_src_size(Some(data.len() as u64)).expect("zstd pledged size");
    }
    let mut input = InBuffer::around(data);
    let mut chunk = Vec::with_capacity(16 * 1024);
    loop {
        chunk.clear();
        let mut out = OutBuffer::around(&mut chunk);
        let directive = if known_size || input.pos() == data.len() {
            ZSTD_EndDirective::ZSTD_e_end
        } else {
            ZSTD_EndDirective::ZSTD_e_continue
        };
        let remaining = cctx.compress_stream2(&mut out, &mut input, directive).expect("zstd compress");
        if !chunk.is_empty() && !sink(&chunk) {
            let _ = cctx.reset(ResetDirective::SessionOnly);
            return false;
        }
        if directive == ZSTD_EndDirective::ZSTD_e_end && remaining == 0 {
            return true;
        }
    }
}

impl Codec for ZstdCodec {
    fn format(&self) -> Format {
        Format::Zstd
    }

    fn self_verifying(&self) -> bool {
        true
    }

    fn probe(&self, data: &[u8]) -> bool {
        data.len() >= 9 && frame_flags(data).is_some_and(|f| !f.has_dict)
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let flags = frame_flags(data).ok_or(DecodeError::BadHeader)?;
        if flags.has_dict {
            return Err(DecodeError::BadHeader);
        }
        // Walks the block headers to find the frame's end without decompressing.
        let size = zstd::zstd_safe::find_frame_compressed_size(data).map_err(|_| DecodeError::InvalidData)?;
        let frame = &data[..size];
        let max = ctx.max_output();
        let content_size = zstd::zstd_safe::get_frame_content_size(frame).ok().flatten();
        if content_size.is_some_and(|n| n > max as u64) {
            return Err(DecodeError::TooLarge(max));
        }
        let mut dctx = DCtx::create();
        let mut out = output_buffer(content_size.map(|n| n.max(1)), max);
        let mut input = InBuffer::around(frame);
        loop {
            if out.len() == out.capacity() {
                grow(&mut out, max)?;
            }
            let pos = out.len();
            let mut output = OutBuffer::around_pos(&mut out, pos);
            let hint = dctx.decompress_stream(&mut output, &mut input).map_err(|_| DecodeError::InvalidData)?;
            if hint == 0 {
                break;
            }
            if input.pos() == frame.len() && out.len() < out.capacity() {
                return Err(DecodeError::Truncated);
            }
        }
        Ok(Decoded { compressed_size: size, body: 0..size, data: out, original_name: None })
    }

    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        let flags = frame_flags(stream)?;
        MATCH_LEVELS.iter().find_map(|&level| {
            let p = ZstdParams { level, checksum: flags.checksum, content_size: flags.content_size };
            let mut pos = 0;
            let finished = compress(&decoded.data, &p, |chunk| {
                let same = stream.get(pos..pos + chunk.len()) == Some(chunk);
                pos += chunk.len();
                same
            });
            (finished && pos == stream.len()).then_some(EncoderParams::Zstd(p))
        })
    }

    fn default_params(&self, stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        let flags = frame_flags(stream);
        EncoderParams::Zstd(ZstdParams {
            level: 3,
            checksum: flags.as_ref().is_some_and(|f| f.checksum),
            content_size: flags.as_ref().is_none_or(|f| f.content_size),
        })
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, p: &EncoderParams) -> Result<EncoderParams, String> {
        match p {
            EncoderParams::Zstd(z) if (-131_072..=22).contains(&z.level) => Ok(p.clone()),
            EncoderParams::Zstd(z) => Err(format!("zstd level {} is out of range", z.level)),
            other => Err(wrong_encoder("zstd", other)),
        }
    }

    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        let base = *params(base);
        [19, 22].into_iter().filter(|&l| l > base.level).map(|level| EncoderParams::Zstd(ZstdParams { level, ..base })).collect()
    }

    fn encode(&self, _stream: &[u8], _decoded: &Decoded, data: &[u8], p: &EncoderParams) -> Vec<u8> {
        let mut out = Vec::new();
        compress(data, params(p), |chunk| {
            out.extend_from_slice(chunk);
            true
        });
        out
    }
}
