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

use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::checksum::crc32;
use crate::codec::{Codec, CompressionParams, DecodeCtx, Format, codec_for};
use crate::deflater::find_params;
use crate::entropy::shannon;

pub const DEFAULT_MIN_SIZE: u64 = 32;
pub const DEFAULT_RAW_MIN_COMPRESSED: u64 = 256;
pub const DEFAULT_RAW_MAX_ENTROPY: f64 = 7.5;
pub const DEFAULT_RAW_MIN_RATIO: f64 = 1.1;
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
/// - On 4 GiB of mixed data (stage 3), chance stored blocks also appeared in structured
///   data: `00 00 00 ff ff` (an empty stored block) occurs wherever a 16-bit counter hits
///   0xFFFF, and a stored block starting in random bytes can run into text. Their output
///   is compressible but the "compressed" stream is no smaller (ratio 1.00-1.05), which no
///   real compressor produces except at level 0. So raw deflate must also compress.
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
    /// Minimum decompressed/compressed ratio for raw deflate.
    #[serde(default = "default_raw_min_ratio")]
    pub raw_min_ratio: f64,
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

fn default_raw_min_ratio() -> f64 {
    DEFAULT_RAW_MIN_RATIO
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            formats: Format::ALL.to_vec(),
            min_size: DEFAULT_MIN_SIZE,
            raw_min_compressed: DEFAULT_RAW_MIN_COMPRESSED,
            raw_max_entropy: Some(DEFAULT_RAW_MAX_ENTROPY),
            raw_min_ratio: DEFAULT_RAW_MIN_RATIO,
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
    scan_with_stats(data, opts).0
}

/// Wall-clock time spent in each scan phase.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanStats {
    pub bytes: u64,
    pub verified_pass: Duration,
    pub raw_pass: Duration,
    pub param_matching: Duration,
}

impl ScanStats {
    pub fn total(&self) -> Duration {
        self.verified_pass + self.raw_pass + self.param_matching
    }
}

/// [`scan`], also reporting how long each phase took.
pub fn scan_with_stats(data: &[u8], opts: &ScanOptions) -> (Vec<FoundStream>, ScanStats) {
    scan_chunked(data, opts, chunk_size(data.len()))
}

/// Work unit size: enough chunks to keep every thread busy, but not so many that
/// per-chunk overhead shows.
fn chunk_size(len: usize) -> usize {
    (len / (rayon::current_num_threads() * 8)).clamp(64 << 10, 4 << 20)
}

/// The scan, parallelised over chunks of `chunk` bytes.
///
/// Each worker records every hit (an accepted stream at an offset) in its chunk without
/// skipping anything. A sequential merge then replays the skip-past and lookahead rules
/// over the sorted hits. `try_at` depends only on the offset and the window end, so this
/// gives exactly the sequential result however the input is split.
fn scan_chunked(data: &[u8], opts: &ScanOptions, chunk: usize) -> (Vec<FoundStream>, ScanStats) {
    let mut stats = ScanStats { bytes: data.len() as u64, ..Default::default() };
    let max_output = usize::try_from(opts.max_output).unwrap_or(usize::MAX);

    let mut formats = opts.formats.clone();
    formats.sort();
    formats.dedup();
    let (verified, unverified): (Vec<&dyn Codec>, Vec<&dyn Codec>) =
        formats.into_iter().map(codec_for).partition(|c| c.self_verifying());

    let t = Instant::now();
    let mut found = Vec::new();
    if !verified.is_empty() {
        let hits = collect_hits(data, &[(0, data.len())], chunk, &verified, opts, max_output);
        found = resolve_verified(hits);
    }
    stats.verified_pass = t.elapsed();

    let t = Instant::now();
    if !unverified.is_empty() {
        let mut gaps = Vec::new();
        let mut pos = 0;
        for s in &found {
            gaps.push((pos, s.offset as usize));
            pos = s.end() as usize;
        }
        gaps.push((pos, data.len()));
        let hits = collect_hits(data, &gaps, chunk, &unverified, opts, max_output);
        found.extend(resolve_unverified(hits));
        found.sort_by_key(|s| s.offset);
    }
    stats.raw_pass = t.elapsed();

    let t = Instant::now();
    if opts.match_params {
        found.par_iter_mut().for_each_init(|| DecodeCtx::new(max_output), |ctx, s| match_params(data, s, ctx));
    }
    stats.param_matching = t.elapsed();
    (found, stats)
}

/// Every hit in each of `ranges`, in offset order. Streams must end within their range.
fn collect_hits(
    data: &[u8],
    ranges: &[(usize, usize)],
    chunk: usize,
    codecs: &[&dyn Codec],
    opts: &ScanOptions,
    max_output: usize,
) -> Vec<FoundStream> {
    // (first offset, last offset + 1, window end)
    let mut work = Vec::new();
    for &(start, end) in ranges {
        let mut pos = start;
        while pos < end {
            let next = (pos + chunk).min(end);
            work.push((pos, next, end));
            pos = next;
        }
    }
    let per_chunk: Vec<Vec<FoundStream>> = work
        .par_iter()
        .map_init(
            || DecodeCtx::new(max_output),
            |ctx, &(from, to, window_end)| {
                (from..to).filter_map(|pos| try_at(data, pos, window_end, codecs, opts, ctx)).collect()
            },
        )
        .collect();
    per_chunk.into_iter().flatten().collect()
}

/// Skip-past for self-verifying formats: take each hit that starts after the last one ends.
fn resolve_verified(hits: Vec<FoundStream>) -> Vec<FoundStream> {
    let mut found: Vec<FoundStream> = Vec::new();
    for hit in hits {
        if found.last().is_none_or(|last| hit.offset >= last.end()) {
            found.push(hit);
        }
    }
    found
}

/// Skip-past with lookahead for unverified formats. An unverified match can be a false
/// positive that starts a little before a real stream, decodes its first bytes as garbage
/// and stops inside it. If a match that starts inside this one runs past its end, the
/// later match is the real stream.
fn resolve_unverified(hits: Vec<FoundStream>) -> Vec<FoundStream> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < hits.len() {
        let mut best = i;
        let mut j = i + 1;
        while j < hits.len() && hits[j].offset < hits[best].end() {
            if hits[j].end() > hits[best].end() {
                best = j;
            }
            j += 1;
        }
        let end = hits[best].end();
        found.push(hits[best].clone());
        i = j;
        while i < hits.len() && hits[i].offset < end {
            i += 1;
        }
    }
    found
}

/// Replace the header-derived params with exact ones if some zlib setting reproduces the stream.
fn match_params(data: &[u8], found: &mut FoundStream, ctx: &mut DecodeCtx) {
    let start = found.offset as usize;
    let stream = &data[start..start + found.compressed_size as usize];
    let Ok(decoded) = codec_for(found.format).decode(stream, ctx) else { return };
    if let Some(p) = find_params(&decoded.data, &stream[decoded.body.clone()], found.params.window_bits) {
        found.params = CompressionParams::exact(p);
    }
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
        if (compressed_size as u64) < opts.raw_min_compressed
            || (out.len() as f64) < opts.raw_min_ratio * compressed_size as f64
        {
            return false;
        }
        max_entropy = match (max_entropy, opts.raw_max_entropy) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    max_entropy.is_none_or(|max| shannon(out) <= max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The original single-threaded scan, kept as the oracle for the parallel one.
    fn scan_sequential(data: &[u8], opts: &ScanOptions) -> Vec<FoundStream> {
        let mut ctx = DecodeCtx::new(usize::try_from(opts.max_output).unwrap_or(usize::MAX));
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
        if opts.match_params {
            for s in &mut found {
                match_params(data, s, &mut ctx);
            }
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
            pos = best.end() as usize;
            found.push(best);
        }
    }

    /// A blob with streams of every format straddling chunk boundaries, back-to-back
    /// streams, raw-deflate false-positive bait, and a zlib stream whose body a raw hit
    /// starting one byte early could swallow.
    fn stress_blob() -> Vec<u8> {
        use zscan_fixtures::*;
        let mut b = Builder::new(21);
        for round in 0..12 {
            b.random(700 + round * 331);
            let p = b.text(3000 + round * 900);
            let encoded = match round % 3 {
                0 => zlib(&p, 6),
                1 => gzip(&p, None),
                _ => deflate(&p, [1, 6, 9][round % 3]),
            };
            b.raw(&encoded);
            if round % 4 == 0 {
                let p = b.records(2000);
                b.raw(&zlib(&p, 1)); // back to back
            }
            b.zeros(round * 17);
        }
        let mut data = b.finish("stress", "").data;
        for f in all() {
            data.extend(f.data);
        }
        data
    }

    #[test]
    fn parallel_matches_sequential_for_any_chunking() {
        let data = stress_blob();
        let opts = ScanOptions::default();
        let expected = scan_sequential(&data, &opts);
        assert!(expected.len() > 30, "blob should contain many streams, got {}", expected.len());
        for chunk in [1, 7, 4096, 65_536, 1 << 20] {
            assert_eq!(scan_chunked(&data, &opts, chunk).0, expected, "chunk size {chunk}");
        }
    }

    #[test]
    fn parallel_matches_sequential_with_loose_raw_filters() {
        // With the raw filters off, random filler produces lots of overlapping raw hits,
        // which exercises the lookahead merge far more than real data does.
        let data = stress_blob();
        let opts = ScanOptions {
            raw_min_compressed: 0,
            raw_max_entropy: None,
            raw_min_ratio: 0.0,
            min_size: 0,
            match_params: false,
            ..Default::default()
        };
        let expected = scan_sequential(&data, &opts);
        assert!(expected.len() > 200, "expected many raw false positives, got {}", expected.len());
        for chunk in [1, 13, 4096] {
            assert_eq!(scan_chunked(&data, &opts, chunk).0, expected, "chunk size {chunk}");
        }
    }
}
