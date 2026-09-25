//! Oodle (cargo feature `oodle`): Kraken, Mermaid, Selkie, Leviathan and Hydra streams,
//! decoded and encoded by the user's own oo2core library, loaded at run time. zscan
//! never includes the library; see [`crate::plugins`] for how it is found.
//!
//! An Oodle stream records neither its decompressed size nor where it ends, and has no
//! real magic number, so decoding needs the decompressed size from outside: a manifest,
//! a length field, or the user. Given that, the compressed size can be read from the
//! stream's block headers for the Kraken-family decoders (Kraken, Mermaid/Selkie,
//! Leviathan; Hydra emits those), which is what lets a scan find streams at all. The
//! older LZNA and BitKnit decoders need the compressed size too.
//!
//! Stream layout (Oodle 2.6+), per 256 KiB of output:
//! - a 2-byte block header: `0xC` in the low nibble of byte 0, bit 6 = stored block,
//!   bit 7 = decoder reset; byte 1 = decoder type (bits 0-6) and a checksum flag (bit 7);
//! - unless stored, a 3-byte big-endian quantum header: 18 bits compressed size - 1, or
//!   all ones plus a flag for a block of one repeated byte; then a 3-byte CRC if the
//!   checksum flag is set, then the compressed data.
//!
//! The stream doesn't record its decompressed size, and Oodle decodes whatever size it is
//! asked for as long as the data allows it. Measured with oo2core 2.9.10: Kraken and
//! Mermaid/Selkie blocks reject any wrong size, but Leviathan blocks also decode to sizes
//! a little smaller and anything larger within the block, stored blocks to any smaller
//! size, and single-byte fills to any size. So the size given is taken on trust; for a
//! scan, the raw filters reject streams of only stored blocks or fills.
//!
//! Encoder output depends on the library version, so exact matches found with one
//! oo2core may not hold with another.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

use libloading::Library;

use super::util::wrong_encoder;
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format, SizeHint};
use crate::params::{EncoderParams, OodleCompressor, OodleParams};
use crate::plugins::{NO_OODLE_DLL, oodle_dll_path};

/// `OodleLZ_Decompress`. Every argument after the fourth has had the same meaning since
/// Oodle 2.3; on x64 there is one calling convention, so older libraries work too.
type DecompressFn = unsafe extern "C" fn(
    comp: *const u8,
    comp_len: isize,
    raw: *mut u8,
    raw_len: isize,
    fuzz_safe: i32,
    check_crc: i32,
    verbosity: i32,
    dec_buf_base: *mut u8,
    dec_buf_size: isize,
    callback: *const c_void,
    callback_data: *mut c_void,
    decoder_memory: *mut c_void,
    decoder_memory_size: isize,
    thread_phase: i32,
) -> isize;

/// `OodleLZ_Compress`.
type CompressFn = unsafe extern "C" fn(
    compressor: i32,
    raw: *const u8,
    raw_len: isize,
    comp: *mut u8,
    level: i32,
    options: *const c_void,
    dictionary_base: *const c_void,
    lrm: *const c_void,
    scratch: *mut c_void,
    scratch_size: isize,
) -> isize;

const FUZZ_SAFE_YES: i32 = 1;
const CHECK_CRC_YES: i32 = 1;
const VERBOSITY_NONE: i32 = 0;
const DECODE_UNTHREADED: i32 = 3;

/// Slack around buffers handed to the library. Some versions read or write a little past
/// the lengths they are given.
const PAD: usize = 64;

/// A loaded oo2core library. Loaded libraries are kept for the life of the process.
pub struct OodleCodec {
    path: PathBuf,
    decompress: DecompressFn,
    compress: Option<CompressFn>,
    _lib: Library,
}

static LOADED: Mutex<Vec<&'static OodleCodec>> = Mutex::new(Vec::new());

/// The codec for the configured library, loading it on first use.
pub(crate) fn codec() -> Result<&'static OodleCodec, String> {
    let path = oodle_dll_path().ok_or(NO_OODLE_DLL)?;
    let mut loaded = LOADED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(codec) = loaded.iter().find(|c| c.path == path) {
        return Ok(codec);
    }
    let codec: &'static OodleCodec = Box::leak(Box::new(load(&path)?));
    loaded.push(codec);
    Ok(codec)
}

/// Load an oo2core library and look up the functions zscan uses.
pub fn load(path: &Path) -> Result<OodleCodec, String> {
    let shown = path.display();
    if !path.is_file() {
        return Err(format!("Oodle library {shown} not found (from --oodle-dll or ZSCAN_OODLE_DLL)"));
    }
    // SAFETY: loading runs the library's initialisation code. The user chose this file
    // as their Oodle library, which is all zscan can go on.
    let lib = unsafe { Library::new(path) }
        .map_err(|e| format!("can't load {shown} as a library ({e}); it must be a 64-bit oo2core build for this OS"))?;
    // SAFETY: the types match oodle2.h for every Oodle 2.x release.
    let decompress = unsafe { lib.get::<DecompressFn>(b"OodleLZ_Decompress\0") }
        .map(|f| *f)
        .map_err(|_| format!("{shown} has no OodleLZ_Decompress; is it an Oodle oo2core library?"))?;
    // SAFETY: as above.
    let compress = unsafe { lib.get::<CompressFn>(b"OodleLZ_Compress\0") }.map(|f| *f).ok();
    Ok(OodleCodec { path: path.to_path_buf(), decompress, compress, _lib: lib })
}

impl OodleCodec {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decode exactly `raw_len` bytes from all of `comp`, or `None`.
    fn decompress(&self, comp: &[u8], raw_len: usize) -> Option<Vec<u8>> {
        let mut input = Vec::with_capacity(comp.len() + PAD);
        input.extend_from_slice(comp);
        input.resize(comp.len() + PAD, 0);
        let mut out = vec![0u8; raw_len + PAD];
        // SAFETY: both buffers are valid for the lengths passed plus PAD, and fuzz-safe
        // mode makes the decoder check every read and write against those lengths.
        let n = unsafe {
            (self.decompress)(
                input.as_ptr(),
                comp.len() as isize,
                out.as_mut_ptr(),
                raw_len as isize,
                FUZZ_SAFE_YES,
                CHECK_CRC_YES,
                VERBOSITY_NONE,
                ptr::null_mut(),
                0,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                DECODE_UNTHREADED,
            )
        };
        (n == raw_len as isize).then(|| {
            out.truncate(raw_len);
            out
        })
    }

    fn compress(&self, data: &[u8], p: &OodleParams) -> Result<Vec<u8>, String> {
        let compress = self.compress.ok_or_else(|| format!("{} has no OodleLZ_Compress", self.path.display()))?;
        if data.is_empty() {
            return Err("Oodle can't encode empty data".into());
        }
        // Far above the library's own bound (a few hundred bytes per 256 KiB block).
        let mut out = vec![0u8; data.len() + data.len() / 16 + 65_536];
        // SAFETY: `out` is larger than any output the library produces for `data`, and
        // null options, dictionary, LRM and scratch select its defaults.
        let n = unsafe {
            compress(
                compressor_id(p.compressor),
                data.as_ptr(),
                data.len() as isize,
                out.as_mut_ptr(),
                p.level,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                0,
            )
        };
        if n <= 0 || n as usize > out.len() {
            return Err(format!("the Oodle library failed to encode with {}", EncoderParams::Oodle(*p)));
        }
        out.truncate(n as usize);
        Ok(out)
    }
}

/// `OodleLZ_Compressor` values.
fn compressor_id(c: OodleCompressor) -> i32 {
    match c {
        OodleCompressor::Kraken => 8,
        OodleCompressor::Mermaid => 9,
        OodleCompressor::Selkie => 11,
        OodleCompressor::Hydra => 12,
        OodleCompressor::Leviathan => 13,
    }
}

const BLOCK: usize = 0x40000;
const KRAKEN: u8 = 6;
const MERMAID: u8 = 10;
const LEVIATHAN: u8 = 12;
const LZNA: u8 = 5;
const BITKNIT: u8 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockHeader {
    decoder: u8,
    stored: bool,
    reset: bool,
    checksums: bool,
}

fn block_header(data: &[u8]) -> Option<BlockHeader> {
    let (&b0, &b1) = (data.first()?, data.get(1)?);
    let decoder = b1 & 0x7f;
    (b0 & 0x3f == 0x0c && matches!(decoder, KRAKEN | MERMAID | LEVIATHAN | LZNA | BITKNIT)).then_some(BlockHeader {
        decoder,
        stored: b0 & 0x40 != 0,
        reset: b0 & 0x80 != 0,
        checksums: b1 & 0x80 != 0,
    })
}

/// Where a stream of `raw_len` output bytes ends, read from its block headers, and how
/// many of its bytes are entropy-coded (not stored blocks or single-byte fills).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Walk {
    compressed: usize,
    evidence: usize,
}

/// Follow the block headers of a Kraken-family stream. `raw_len` of `None` walks until
/// `data` runs out, for a stream whose extent is already known.
fn walk(data: &[u8], raw_len: Option<usize>) -> Result<Walk, DecodeError> {
    let (mut pos, mut produced, mut evidence) = (0, 0, 0);
    loop {
        match raw_len {
            Some(raw) if produced >= raw => break,
            None if pos >= data.len() => break,
            _ => {}
        }
        let h = block_header(&data[pos..]).ok_or(DecodeError::InvalidData)?;
        if pos == 0 && !h.reset {
            return Err(DecodeError::BadHeader);
        }
        if !matches!(h.decoder, KRAKEN | MERMAID | LEVIATHAN) {
            return Err(DecodeError::SizeRequired("compressed"));
        }
        pos += 2;
        let chunk = match raw_len {
            Some(raw) => (raw - produced).min(BLOCK),
            None => BLOCK,
        };
        if h.stored {
            // Without a size, the last block's output size is whatever the stream has left.
            pos += if raw_len.is_some() { chunk } else { chunk.min(data.len() - pos) };
        } else {
            let q = data.get(pos..pos + 3).ok_or(DecodeError::Truncated)?;
            let v = usize::from(q[0]) << 16 | usize::from(q[1]) << 8 | usize::from(q[2]);
            let size = v & 0x3ffff;
            if size == 0x3ffff {
                if v >> 18 != 1 {
                    return Err(DecodeError::InvalidData);
                }
                pos += 4; // a block of one repeated byte
            } else {
                let size = size + 1;
                if size > chunk {
                    return Err(DecodeError::InvalidData);
                }
                pos += 3 + if h.checksums { 3 } else { 0 } + size;
                if size < chunk {
                    evidence += size;
                }
            }
        }
        if pos > data.len() {
            return Err(DecodeError::Truncated);
        }
        produced += chunk;
    }
    Ok(Walk { compressed: pos, evidence })
}

/// Encoder settings that produce a stream whose first block uses `decoder`, in the
/// order worth trying.
fn compressors_for(decoder: u8) -> &'static [OodleCompressor] {
    match decoder {
        MERMAID => &[OodleCompressor::Mermaid, OodleCompressor::Selkie],
        LEVIATHAN => &[OodleCompressor::Leviathan],
        _ => &[OodleCompressor::Kraken],
    }
}

/// Normal first, then the Optimal levels games ship with, then the fast ones.
const LEVELS: [i32; 14] = [4, 5, 6, 7, 8, 9, 3, 2, 1, -1, -2, -3, -4, 0];

fn params(p: &EncoderParams) -> &OodleParams {
    match p {
        EncoderParams::Oodle(p) => p,
        other => panic!("{}", wrong_encoder("oodle", other)),
    }
}

impl Codec for OodleCodec {
    fn format(&self) -> Format {
        Format::Oodle
    }

    fn self_verifying(&self) -> bool {
        false
    }

    fn needs_size(&self) -> bool {
        true
    }

    fn probe(&self, data: &[u8]) -> bool {
        block_header(data).is_some_and(|h| h.reset)
    }

    fn decode(&self, _data: &[u8], _ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        Err(DecodeError::SizeRequired("decompressed"))
    }

    fn decode_with_hint(&self, data: &[u8], hint: SizeHint, ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let raw_len = hint.decompressed.ok_or(DecodeError::SizeRequired("decompressed"))?;
        if raw_len == 0 || !self.probe(data) {
            return Err(DecodeError::BadHeader);
        }
        if raw_len > ctx.max_output() {
            return Err(DecodeError::TooLarge(ctx.max_output()));
        }
        let end = |raw_len| match hint.compressed {
            Some(c) if c > data.len() => Err(DecodeError::Truncated),
            Some(c) => Ok(c),
            None => walk(data, Some(raw_len)).map(|w| w.compressed),
        };
        let compressed = end(raw_len)?;
        let out = self.decompress(&data[..compressed], raw_len).ok_or(DecodeError::InvalidData)?;
        Ok(Decoded { compressed_size: compressed, body: 0..compressed, data: out, original_name: None })
    }

    /// Stored blocks and single-byte fills prove nothing, like stored deflate blocks.
    fn evidence(&self, stream: &[u8]) -> usize {
        walk(stream, None).map_or(stream.len(), |w| w.evidence)
    }

    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        let decoder = block_header(stream)?.decoder;
        for &compressor in compressors_for(decoder) {
            for level in LEVELS {
                let p = OodleParams { compressor, level };
                if self.compress(&decoded.data, &p).is_ok_and(|s| s == stream) {
                    return Some(EncoderParams::Oodle(p));
                }
            }
        }
        None
    }

    fn default_params(&self, stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        let decoder = block_header(stream).map_or(KRAKEN, |h| h.decoder);
        EncoderParams::Oodle(OodleParams { compressor: compressors_for(decoder)[0], level: 4 })
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, p: &EncoderParams) -> Result<EncoderParams, String> {
        match p {
            EncoderParams::Oodle(o) if (-4..=9).contains(&o.level) => Ok(p.clone()),
            EncoderParams::Oodle(o) => Err(format!("Oodle level {} is not -4 to 9", o.level)),
            other => Err(wrong_encoder("oodle", other)),
        }
    }

    /// Stronger levels of the same compressor: the reader may only have its decoder.
    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        let base = *params(base);
        [7, 9]
            .into_iter()
            .filter(|&level| level > base.level)
            .map(|level| EncoderParams::Oodle(OodleParams { level, ..base }))
            .collect()
    }

    fn encode(&self, _stream: &[u8], _decoded: &Decoded, data: &[u8], p: &EncoderParams) -> Result<Vec<u8>, String> {
        self.compress(data, params(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream of stored blocks, which any Oodle decoder accepts.
    fn stored_stream(data: &[u8], decoder: u8) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, chunk) in data.chunks(BLOCK).enumerate() {
            out.push(if i == 0 { 0xcc } else { 0x4c });
            out.push(decoder);
            out.extend_from_slice(chunk);
        }
        out
    }

    #[test]
    fn headers() {
        assert_eq!(block_header(&[0x8c, 0x06]), Some(BlockHeader { decoder: KRAKEN, stored: false, reset: true, checksums: false }));
        assert_eq!(block_header(&[0xcc, 0x8a]), Some(BlockHeader { decoder: MERMAID, stored: true, reset: true, checksums: true }));
        assert_eq!(block_header(&[0x8c, 0x07]), None, "unknown decoder");
        assert_eq!(block_header(&[0x9c, 0x06]), None, "reserved bits set");
        assert_eq!(block_header(&[0x8d, 0x06]), None);
        assert_eq!(block_header(&[0x8c]), None);
    }

    #[test]
    fn walk_finds_the_end() {
        let data: Vec<u8> = (0..BLOCK * 2 + 1000).map(|i| (i * 7) as u8).collect();
        let stream = stored_stream(&data, KRAKEN);
        let mut padded = stream.clone();
        padded.extend_from_slice(&[0x8c, 0x06, 0xff, 0xff, 0xff]);
        assert_eq!(walk(&padded, Some(data.len())), Ok(Walk { compressed: stream.len(), evidence: 0 }));
        assert_eq!(walk(&stream, None), Ok(Walk { compressed: stream.len(), evidence: 0 }));
        assert_eq!(walk(&stream[..stream.len() - 1], Some(data.len())), Err(DecodeError::Truncated));
        assert_eq!(walk(&stream, Some(data.len() + 1)), Err(DecodeError::Truncated), "last stored block too short");
        let mut one_block = stored_stream(&data[..BLOCK], KRAKEN);
        one_block.extend_from_slice(&[0; 32]);
        assert_eq!(walk(&one_block, Some(BLOCK + 10)), Err(DecodeError::InvalidData), "no second block header");

        // Compressed quanta: 3-byte size header, optional CRC, data.
        let mut q = vec![0x8c, 0x86, 0x00, 0x00, 0x09, 1, 2, 3]; // 10 bytes, with checksum
        q.extend_from_slice(&[0xaa; 10]);
        q.extend_from_slice(&[0x0c, 0x06, 0x07, 0xff, 0xff, 0x55]); // a fill block
        assert_eq!(walk(&q, Some(BLOCK + 5)), Ok(Walk { compressed: q.len(), evidence: 10 }));
        assert_eq!(walk(&q, Some(5)), Err(DecodeError::InvalidData), "compressed size above the block's output");
    }

    #[test]
    fn walk_needs_a_reset_and_a_known_decoder() {
        assert_eq!(walk(&[0x0c, 0x06, 0, 0, 0, 0], Some(10)), Err(DecodeError::BadHeader));
        assert_eq!(walk(&[0x8c, BITKNIT, 0, 0], Some(10)), Err(DecodeError::SizeRequired("compressed")));
    }

    #[test]
    fn missing_or_bad_library_is_a_clear_error() {
        let err = load(Path::new("no/such/oo2core_9_win64.dll")).err().unwrap();
        assert!(err.contains("not found") && err.contains("--oodle-dll"), "{err}");
        let not_a_lib = std::env::current_exe().unwrap().with_file_name("definitely-not-oodle.txt");
        std::fs::write(&not_a_lib, b"hello").unwrap();
        let err = load(&not_a_lib).err().unwrap();
        std::fs::remove_file(&not_a_lib).ok();
        assert!(err.contains("can't load"), "{err}");
    }
}
