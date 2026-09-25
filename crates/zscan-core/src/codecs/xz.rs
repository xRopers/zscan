//! .xz streams: a 12-byte header (magic, flags, CRC-32), blocks, an index and a footer,
//! all CRC-protected, with an optional check (CRC-32, CRC-64 or SHA-256) of each block's
//! data. Only LZMA2-only filter chains can be matched exactly; any stream liblzma can
//! decode is found and extracted.

use xz2::stream::{Action, Check, Error as XzError, Filters, LzmaOptions, MtStreamBuilder, Status, Stream};

use super::util::{grow, output_buffer, wrong_encoder};
use crate::checksum::crc32;
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format};
use crate::params::{EncoderParams, XzCheck, XzParams};

pub struct XzCodec;

const MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0];
const HEADER_LEN: usize = 12;
const PRESET_EXTREME: u32 = 1 << 31;
const LZMA2_FILTER_ID: u64 = 0x21;
/// An LZMA2 encoder needs roughly 10x its dictionary in memory (674 MiB at preset 9's
/// 64 MiB). Param matching runs on every core, so encoders with dictionaries above this
/// run one at a time.
const BIG_DICT: u32 = 16 << 20;
static BIG_ENCODER: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn header_check(data: &[u8]) -> Option<XzCheck> {
    if data.len() < HEADER_LEN || !data.starts_with(&MAGIC) || data[6] != 0 {
        return None;
    }
    if crc32(&data[6..8]) != u32::from_le_bytes(data[8..12].try_into().unwrap()) {
        return None;
    }
    match data[7] {
        0x00 => Some(XzCheck::None),
        0x01 => Some(XzCheck::Crc32),
        0x04 => Some(XzCheck::Crc64),
        0x0a => Some(XzCheck::Sha256),
        _ => None,
    }
}

/// Reads a variable-length integer (7 bits per byte, low first). Returns (value, bytes).
fn read_vli(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &b) in data.iter().take(9).enumerate() {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// What the first block header says: whether it records its sizes (only liblzma's
/// multithreaded encoder writes them) and the LZMA2 dictionary size. `None` if there is
/// no block or the filter chain is not plain LZMA2.
fn first_block(stream: &[u8]) -> Option<(bool, u32)> {
    let size_byte = *stream.get(HEADER_LEN)?;
    if size_byte == 0 {
        return None; // index indicator: an empty stream
    }
    let header = stream.get(HEADER_LEN..HEADER_LEN + (usize::from(size_byte) + 1) * 4)?;
    let flags = header[1];
    if flags & 0x03 != 0 {
        return None; // more than one filter (e.g. a BCJ filter before LZMA2)
    }
    let mut pos = 2;
    for present in [flags & 0x40 != 0, flags & 0x80 != 0] {
        if present {
            pos += read_vli(&header[pos..])?.1;
        }
    }
    let (id, n) = read_vli(&header[pos..])?;
    pos += n;
    let (props_len, n) = read_vli(&header[pos..])?;
    pos += n;
    if id != LZMA2_FILTER_ID || props_len != 1 {
        return None;
    }
    let bits = u32::from(*header.get(pos)?);
    let dict_size = match bits {
        0..=39 => (2 | (bits & 1)) << (bits / 2 + 11),
        40 => u32::MAX,
        _ => return None,
    };
    Some((flags & 0xc0 != 0, dict_size))
}

fn params(p: &EncoderParams) -> &XzParams {
    match p {
        EncoderParams::Xz(p) => p,
        other => panic!("{}", wrong_encoder("xz", other)),
    }
}

fn to_check(c: XzCheck) -> Check {
    match c {
        XzCheck::None => Check::None,
        XzCheck::Crc32 => Check::Crc32,
        XzCheck::Crc64 => Check::Crc64,
        XzCheck::Sha256 => Check::Sha256,
    }
}

fn encoder(p: &XzParams) -> Stream {
    let preset = p.preset | if p.extreme { PRESET_EXTREME } else { 0 };
    let mut opts = LzmaOptions::new_preset(preset).expect("xz preset");
    opts.dict_size(p.dict_size);
    let mut filters = Filters::new();
    filters.lzma2(&opts);
    if p.threaded {
        // The multithreaded encoder's output doesn't depend on the thread count.
        MtStreamBuilder::new().threads(1).filters(filters).check(to_check(p.check)).encoder()
    } else {
        Stream::new_stream_encoder(&filters, to_check(p.check))
    }
    .expect("xz encoder")
}

/// Compress `data`, handing output to `sink` in chunks; false if `sink` stopped early.
fn compress(data: &[u8], p: &XzParams, mut sink: impl FnMut(&[u8]) -> bool) -> bool {
    let mut s = encoder(p);
    let mut chunk = Vec::with_capacity(16 * 1024);
    loop {
        chunk.clear();
        let status = s.process_vec(&data[s.total_in() as usize..], &mut chunk, Action::Finish).expect("xz compress");
        if !chunk.is_empty() && !sink(&chunk) {
            return false;
        }
        if status == Status::StreamEnd {
            return true;
        }
    }
}

impl Codec for XzCodec {
    fn format(&self) -> Format {
        Format::Xz
    }

    fn self_verifying(&self) -> bool {
        true
    }

    fn probe(&self, data: &[u8]) -> bool {
        header_check(data).is_some()
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        header_check(data).ok_or(DecodeError::BadHeader)?;
        let max = ctx.max_output();
        // No CONCATENATED flag: stop at the end of this stream.
        let mut s = Stream::new_stream_decoder(u64::MAX, 0).map_err(|_| DecodeError::BadHeader)?;
        let mut out = output_buffer(None, max);
        loop {
            if out.len() == out.capacity() {
                grow(&mut out, max)?;
            }
            let (in_before, out_before) = (s.total_in(), out.len());
            let status = s.process_vec(&data[s.total_in() as usize..], &mut out, Action::Run).map_err(|e| match e {
                XzError::Format | XzError::Options | XzError::UnsupportedCheck => DecodeError::BadHeader,
                _ => DecodeError::InvalidData,
            })?;
            if status == Status::StreamEnd {
                break;
            }
            let stalled = s.total_in() == in_before && out.len() == out_before;
            if stalled || (s.total_in() as usize == data.len() && out.len() < out.capacity()) {
                return Err(DecodeError::Truncated);
            }
        }
        let size = s.total_in() as usize;
        Ok(Decoded { compressed_size: size, body: 0..size, data: out, original_name: None })
    }

    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        let check = header_check(stream)?;
        let (threaded, dict_size) = first_block(stream)?;
        let _one_at_a_time = (dict_size > BIG_DICT).then(|| BIG_ENCODER.lock().unwrap_or_else(|e| e.into_inner()));
        // With the dictionary fixed, presets 7-9 equal 6; they are still tried so a
        // stream is recorded under the lowest preset that reproduces it.
        for preset in [6, 0, 1, 2, 3, 4, 5, 7, 8, 9] {
            for extreme in [false, true] {
                let p = XzParams { preset, extreme, check, dict_size, threaded };
                let mut pos = 0;
                let finished = compress(&decoded.data, &p, |chunk| {
                    let same = stream.get(pos..pos + chunk.len()) == Some(chunk);
                    pos += chunk.len();
                    same
                });
                if finished && pos == stream.len() {
                    return Some(EncoderParams::Xz(p));
                }
            }
        }
        None
    }

    fn default_params(&self, stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        let (threaded, dict_size) = first_block(stream).unwrap_or((false, 8 << 20));
        let check = header_check(stream).unwrap_or(XzCheck::Crc64);
        EncoderParams::Xz(XzParams { preset: 6, extreme: false, check, dict_size, threaded })
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, p: &EncoderParams) -> Result<EncoderParams, String> {
        match p {
            EncoderParams::Xz(x) if x.preset <= 9 && (4096..=1536 << 20).contains(&x.dict_size) => Ok(p.clone()),
            EncoderParams::Xz(x) => Err(format!("invalid xz settings {x:?}")),
            other => Err(wrong_encoder("xz", other)),
        }
    }

    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        let strongest = EncoderParams::Xz(XzParams { preset: 9, extreme: true, ..*params(base) });
        if *base == strongest { vec![] } else { vec![strongest] }
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
