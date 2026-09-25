//! Reinjecting edited streams (the packzip replacement).
//!
//! For each stream in the manifest:
//! - No edit: the original bytes are kept untouched.
//! - Edited: the new data is compressed with the params matched at scan time (or zlib's
//!   defaults), then with stronger settings if that doesn't fit the original slot. The
//!   original header is reused, the trailer recomputed, and leftover space zero-filled.
//!
//! Nothing is returned for writing unless every stream fits and every stream in the
//! output decodes to the intended data.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

use crate::checksum::crc32;
use crate::codec::{Codec, CompressionParams, DecodeCtx, Decoded, Format, Strategy, codec_for};
use crate::deflater::{DeflateParams, compress_raw};
use crate::error::{Error, Result, io_err};
use crate::extract::decode_stream;
use crate::manifest::{Manifest, StreamEntry, is_safe_filename};

#[derive(Debug, Clone)]
pub struct PackOptions {
    /// Refuse to run if the input's size or CRC-32 differs from the manifest.
    pub verify_source: bool,
    /// Let a stream grow into the zero bytes that follow it (never past the next stream).
    /// Only safe when whatever reads the file finds the stream's end by decoding it.
    pub use_zero_slack: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self { verify_source: true, use_zero_slack: false }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// No edit; original bytes kept.
    Unchanged,
    Repacked {
        new_size: u64,
        params: DeflateParams,
        /// True when the settings that reproduce the original stream were good enough.
        reused_original_params: bool,
        /// Bytes of trailing zero slack the new stream grew into.
        slack_used: u64,
    },
    /// Even the strongest settings tried don't fit.
    TooLarge { best_size: u64, available: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamPlan {
    pub id: u32,
    pub offset: u64,
    pub format: Format,
    pub original_size: u64,
    #[serde(flatten)]
    pub outcome: Outcome,
}

impl StreamPlan {
    pub fn new_size(&self) -> u64 {
        match self.outcome {
            Outcome::Unchanged => self.original_size,
            Outcome::Repacked { new_size, .. } => new_size,
            Outcome::TooLarge { best_size, .. } => best_size,
        }
    }

    pub fn delta(&self) -> i64 {
        self.new_size() as i64 - self.original_size as i64
    }
}

#[derive(Debug)]
pub struct PackResult {
    /// One entry per manifest stream, in offset order.
    pub streams: Vec<StreamPlan>,
    /// The packed file. `None` if any stream didn't fit.
    pub data: Option<Vec<u8>>,
    /// Manifest describing the packed file, so it can be extracted and packed again.
    /// Its `source.path` is copied from the input manifest; callers should update it.
    pub manifest: Option<Manifest>,
}

impl PackResult {
    pub fn failures(&self) -> impl Iterator<Item = &StreamPlan> {
        self.streams.iter().filter(|s| matches!(s.outcome, Outcome::TooLarge { .. }))
    }

    pub fn repacked(&self) -> impl Iterator<Item = &StreamPlan> {
        self.streams.iter().filter(|s| matches!(s.outcome, Outcome::Repacked { .. }))
    }
}

/// Read edited stream files from `dir` (as written by extract). Files that are missing,
/// or still identical to the original stream, are not edits.
pub fn load_edits(dir: &Path, manifest: &Manifest) -> Result<BTreeMap<u32, Vec<u8>>> {
    let mut edits = BTreeMap::new();
    for entry in &manifest.streams {
        if !is_safe_filename(&entry.file) {
            return Err(Error::BadFilename(entry.file.clone()));
        }
        let path = dir.join(&entry.file);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(&path)(e)),
        };
        if bytes.len() as u64 != entry.decompressed_size || crc32(&bytes) != entry.crc32 {
            edits.insert(entry.id, bytes);
        }
    }
    Ok(edits)
}

/// Build the packed file from `data`, the `manifest` it was scanned with, and new
/// contents for some streams (keyed by stream id).
pub fn pack(
    data: &[u8],
    manifest: &Manifest,
    edits: &BTreeMap<u32, Vec<u8>>,
    opts: &PackOptions,
) -> Result<PackResult> {
    if opts.verify_source {
        manifest.source.check(data)?;
    }
    let streams = sorted_streams(manifest, data.len())?;
    if let Some(id) = edits.keys().find(|id| !manifest.streams.iter().any(|s| s.id == **id)) {
        return Err(Error::InvalidManifest(format!("edit given for unknown stream id {id}")));
    }

    let largest = streams
        .iter()
        .map(|s| s.decompressed_size)
        .chain(edits.values().map(|v| v.len() as u64))
        .max()
        .unwrap_or(0);
    let mut ctx = DecodeCtx::new(usize::try_from(largest).unwrap_or(usize::MAX));
    let mut out = data.to_vec();
    let mut plans = Vec::with_capacity(streams.len());

    for (i, entry) in streams.iter().enumerate() {
        let mut plan = StreamPlan {
            id: entry.id,
            offset: entry.offset,
            format: entry.format,
            original_size: entry.compressed_size,
            outcome: Outcome::Unchanged,
        };
        let Some(new_data) = edits.get(&entry.id) else {
            plans.push(plan);
            continue;
        };

        // Decoding the original confirms it is still intact and locates its header.
        let original = decode_stream(data, entry, &mut ctx)?;
        let start = entry.offset as usize;
        let end = entry.end() as usize;
        let header = &data[start..start + original.body.start];
        let next_start = streams.get(i + 1).map_or(data.len(), |s| s.offset as usize);
        let slack = if opts.use_zero_slack { data[end..next_start].iter().take_while(|&&b| b == 0).count() } else { 0 };
        let available = end - start + slack;

        let first = first_params(entry, &original)?;
        ctx.recycle(original.data);
        let (stream, params) = fit(codec_for(entry.format), header, new_data, first, available);

        plan.outcome = if stream.len() > available {
            Outcome::TooLarge { best_size: stream.len() as u64, available: available as u64 }
        } else {
            out[start..start + stream.len()].copy_from_slice(&stream);
            if start + stream.len() < end {
                out[start + stream.len()..end].fill(0);
            }
            Outcome::Repacked {
                new_size: stream.len() as u64,
                params,
                reused_original_params: entry.params.exact_match && params == first,
                slack_used: (start + stream.len()).saturating_sub(end) as u64,
            }
        };
        plans.push(plan);
    }

    if plans.iter().any(|p| matches!(p.outcome, Outcome::TooLarge { .. })) {
        return Ok(PackResult { streams: plans, data: None, manifest: None });
    }
    verify(&out, &streams, &plans, edits, &mut ctx)?;
    let manifest = packed_manifest(manifest, &plans, edits, &out);
    Ok(PackResult { streams: plans, data: Some(out), manifest: Some(manifest) })
}

/// Manifest streams in offset order, checked to be in bounds and non-overlapping.
fn sorted_streams(manifest: &Manifest, len: usize) -> Result<Vec<&StreamEntry>> {
    let mut streams: Vec<&StreamEntry> = manifest.streams.iter().collect();
    streams.sort_by_key(|s| s.offset);
    for pair in streams.windows(2) {
        if pair[0].end() > pair[1].offset {
            return Err(Error::InvalidManifest(format!("streams {} and {} overlap", pair[0].id, pair[1].id)));
        }
    }
    if let Some(last) = streams.last() {
        if last.end() > len as u64 {
            return Err(Error::InvalidManifest(format!("stream {} runs past the end of the input", last.id)));
        }
    }
    Ok(streams)
}

/// Settings for the first compression attempt: the exact match from the scan if there
/// is one, else zlib's defaults. Never uses a larger window than the original header
/// declares, since the reader may only provide that much.
fn first_params(entry: &StreamEntry, original: &Decoded) -> Result<DeflateParams> {
    let params = match entry.params.deflate_params().filter(|_| entry.params.exact_match) {
        Some(p) => p,
        None => DeflateParams::zlib_default(entry.params.window_bits.unwrap_or(15)),
    };
    if !params.is_valid() {
        return Err(Error::InvalidManifest(format!("stream {} has invalid params {params}", entry.id)));
    }
    let cap = original.params.window_bits.unwrap_or(15);
    Ok(DeflateParams { window_bits: params.window_bits.min(cap), ..params })
}

/// Compress with `first`; if that doesn't fit in `available` bytes, also try stronger
/// settings with the same window and keep the smallest result.
fn fit(codec: &dyn Codec, header: &[u8], data: &[u8], first: DeflateParams, available: usize) -> (Vec<u8>, DeflateParams) {
    let build = |p: &DeflateParams| codec.wrap(header, &compress_raw(data, p), data);
    let mut best = (build(&first), first);
    if best.0.len() <= available {
        return best;
    }
    for mem_level in [9, 8] {
        for strategy in [Strategy::Default, Strategy::Filtered] {
            let p = DeflateParams { level: 9, window_bits: first.window_bits, mem_level, strategy };
            if p == first {
                continue;
            }
            let stream = build(&p);
            if stream.len() < best.0.len() {
                best = (stream, p);
            }
        }
    }
    best
}

/// Decode every stream from the packed output: unchanged ones must still match the
/// manifest, repacked ones must decode to exactly the edited data.
fn verify(
    out: &[u8],
    streams: &[&StreamEntry],
    plans: &[StreamPlan],
    edits: &BTreeMap<u32, Vec<u8>>,
    ctx: &mut DecodeCtx,
) -> Result<()> {
    for (entry, plan) in streams.iter().zip(plans) {
        let fail = |reason: String| Error::Verify { id: entry.id, offset: entry.offset, reason };
        let decoded = match plan.outcome {
            Outcome::Unchanged => decode_stream(out, entry, ctx).map_err(|e| fail(e.to_string()))?,
            Outcome::Repacked { new_size, .. } => {
                let decoded = codec_for(entry.format)
                    .decode(&out[entry.offset as usize..], ctx)
                    .map_err(|e| fail(format!("{} decode failed: {e}", entry.format)))?;
                if decoded.compressed_size as u64 != new_size {
                    return Err(fail(format!("stream is {} bytes, expected {new_size}", decoded.compressed_size)));
                }
                if decoded.data != edits[&entry.id] {
                    return Err(fail("decompressed data differs from the edited file".into()));
                }
                decoded
            }
            Outcome::TooLarge { .. } => unreachable!("verify only runs when every stream fits"),
        };
        ctx.recycle(decoded.data);
    }
    Ok(())
}

fn packed_manifest(original: &Manifest, plans: &[StreamPlan], edits: &BTreeMap<u32, Vec<u8>>, out: &[u8]) -> Manifest {
    let mut manifest = original.clone();
    manifest.source.size = out.len() as u64;
    manifest.source.crc32 = crc32(out);
    for entry in &mut manifest.streams {
        let Some(plan) = plans.iter().find(|p| p.id == entry.id) else { continue };
        if let Outcome::Repacked { new_size, params, .. } = plan.outcome {
            let new_data = &edits[&entry.id];
            entry.compressed_size = new_size;
            entry.decompressed_size = new_data.len() as u64;
            entry.crc32 = crc32(new_data);
            // The new body was made with exactly these settings.
            entry.params = CompressionParams::exact(params);
        }
    }
    manifest
}
