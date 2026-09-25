//! Finding compressed streams.
//!
//! Scanning runs in two passes:
//! 1. Self-verifying formats (gzip, zlib) across the whole input.
//! 2. Raw deflate only in the gaps between pass-1 streams. Raw deflate has no checksum,
//!    so it could otherwise start a few bytes early and swallow a real stream.
//!
//! In both passes a found stream is skipped over whole, so nothing inside it is re-reported.
//! The one exception is an unverified (raw deflate) match: offsets inside it are still tried
//! in case it is a misaligned false positive that overlaps the start of a real stream.

use serde::{Deserialize, Serialize};

use crate::checksum::crc32;
use crate::codec::{Codec, CompressionParams, DecodeCtx, Format, codec_for};
use crate::deflater::find_params;
use crate::entropy::shannon;

pub const DEFAULT_MIN_SIZE: u64 = 32;
pub const DEFAULT_RAW_MIN_COMPRESSED: u64 = 256;
pub const DEFAULT_RAW_MAX_ENTROPY: f64 = 7.5;
pub const DEFAULT_MAX_OUTPUT: u64 = 1 << 30;

/// False-positive filters and limits. Recorded in the manifest so a scan can be repeated.
///
/// Raw deflate has no checksum, so it gets two extra filters. Measured on 256 MiB of
/// random bytes (stage 1):
/// - Garbage that happens to decode is almost always a fixed-Huffman block under ~100
///   compressed bytes; none reached 256. Compressed size is the amount of input that
///   decoded without error, so it is the evidence that counts, not output size.
/// - Longer false positives are stored blocks whose LEN/NLEN matched by chance. Their
///   content is the random input, with entropy ~8 bits/byte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanOptions {
    pub formats: Vec<Format>,
    /// Minimum decompressed size, in bytes.
    pub min_size: u64,
    /// Minimum compressed size for raw deflate.
    pub raw_min_compressed: u64,
    /// Reject raw deflate whose output entropy is above this (bits per byte).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_max_entropy: Option<f64>,
    /// Minimum decompressed/compressed ratio.
    pub min_ratio: f64,
    /// Reject any stream whose output entropy is above this (bits per byte).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entropy: Option<f64>,
    /// Largest decompressed size of any single stream.
    pub max_output: u64,
    /// Search for zlib settings that reproduce each stream exactly (see [`find_params`]).
    #[serde(default = "yes")]
    pub match_params: bool,
}

fn yes() -> bool {
    true
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            formats: Format::ALL.to_vec(),
            min_size: DEFAULT_MIN_SIZE,
            raw_min_compressed: DEFAULT_RAW_MIN_COMPRESSED,
            raw_max_entropy: Some(DEFAULT_RAW_MAX_ENTROPY),
            min_ratio: 0.0,
            max_entropy: None,
            max_output: DEFAULT_MAX_OUTPUT,
            match_params: true,
        }
    }
}

/// A stream found by [`scan`]. The decompressed data is not kept; extract re-decodes it.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundStream {
    pub offset: u64,
    pub format: Format,
    pub compressed_size: u64,
    pub decompressed_size: u64,
    /// CRC-32 of the decompressed data.
    pub crc32: u32,
    pub params: CompressionParams,
    pub original_name: Option<String>,
}

impl FoundStream {
    pub fn end(&self) -> u64 {
        self.offset + self.compressed_size
    }
}

/// Find every stream in `data` that passes the filters in `opts`, sorted by offset.
pub fn scan(data: &[u8], opts: &ScanOptions) -> Vec<FoundStream> {
    let max_output = usize::try_from(opts.max_output).unwrap_or(usize::MAX);
    let mut ctx = DecodeCtx::new(max_output);

    let mut formats = opts.formats.clone();
    formats.sort();
    formats.dedup();
    let (verified, unverified): (Vec<&dyn Codec>, Vec<&dyn Codec>) =
        formats.into_iter().map(codec_for).partition(|c| c.self_verifying());

    let mut found = Vec::new();
    scan_range(data, 0, data.len(), &verified, opts, &mut ctx, &mut found);

    if !unverified.is_empty() {
        let mut gaps = Vec::new();
        let mut pos = 0;
        for s in &found {
            gaps.push((pos, s.offset as usize));
            pos = s.end() as usize;
        }
        gaps.push((pos, data.len()));
        for (start, end) in gaps {
            scan_range(data, start, end, &unverified, opts, &mut ctx, &mut found);
        }
        found.sort_by_key(|s| s.offset);
    }
    found
}

/// Scan `data[start..end]`. Streams must lie entirely within the range.
fn scan_range(
    data: &[u8],
    start: usize,
    end: usize,
    codecs: &[&dyn Codec],
    opts: &ScanOptions,
    ctx: &mut DecodeCtx,
    found: &mut Vec<FoundStream>,
) {
    let mut pos = start;
    while pos < end {
        let Some(mut best) = try_at(data, pos, end, codecs, opts, ctx) else {
            pos += 1;
            continue;
        };
        // An unverified match can be a false positive that starts a little before a real
        // stream, decodes its first bytes as garbage and stops inside it. If a match that
        // starts inside this one runs past its end, the later match is the real stream.
        if !codec_for(best.format).self_verifying() {
            let mut p = best.offset as usize + 1;
            while p < best.end() as usize {
                if let Some(other) = try_at(data, p, end, codecs, opts, ctx) {
                    if other.end() > best.end() {
                        best = other;
                    }
                }
                p += 1;
            }
        }
        if opts.match_params {
            match_params(data, &mut best, ctx);
        }
        pos = best.end() as usize;
        found.push(best);
    }
}

/// Replace the header-derived params with exact ones if some zlib setting reproduces the stream.
fn match_params(data: &[u8], found: &mut FoundStream, ctx: &mut DecodeCtx) {
    let start = found.offset as usize;
    let stream = &data[start..start + found.compressed_size as usize];
    let Ok(decoded) = codec_for(found.format).decode(stream, ctx) else { return };
    if let Some(p) = find_params(&decoded.data, &stream[decoded.body.clone()], found.params.window_bits) {
        found.params = CompressionParams::exact(p);
    }
    ctx.recycle(decoded.data);
}

/// The first codec whose stream at `pos` decodes and passes the filters.
fn try_at(
    data: &[u8],
    pos: usize,
    end: usize,
    codecs: &[&dyn Codec],
    opts: &ScanOptions,
    ctx: &mut DecodeCtx,
) -> Option<FoundStream> {
    let window = &data[pos..end];
    for codec in codecs {
        if !codec.probe(window) {
            continue;
        }
        let Ok(decoded) = codec.decode(window, ctx) else { continue };
        let format = codec.format();
        let result = accept(format, decoded.compressed_size, &decoded.data, opts).then(|| FoundStream {
            offset: pos as u64,
            format,
            compressed_size: decoded.compressed_size as u64,
            decompressed_size: decoded.data.len() as u64,
            crc32: crc32(&decoded.data),
            params: decoded.params.clone(),
            original_name: decoded.original_name.clone(),
        });
        ctx.recycle(decoded.data);
        if result.is_some() {
            return result;
        }
    }
    None
}

fn accept(format: Format, compressed_size: usize, out: &[u8], opts: &ScanOptions) -> bool {
    if (out.len() as u64) < opts.min_size || (out.len() as f64) < opts.min_ratio * compressed_size as f64 {
        return false;
    }
    let mut max_entropy = opts.max_entropy;
    if !codec_for(format).self_verifying() {
        if (compressed_size as u64) < opts.raw_min_compressed {
            return false;
        }
        max_entropy = match (max_entropy, opts.raw_max_entropy) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    max_entropy.is_none_or(|max| shannon(out) <= max)
}
