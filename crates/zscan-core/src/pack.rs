//! Reinjecting edited streams (the packzip replacement).
//!
//! For each stream in the manifest:
//! - No edit: the original bytes are kept untouched.
//! - Edited: the new data is compressed with the params matched at scan time (or zlib's
//!   defaults), then with stronger settings if that doesn't fit the original slot. The
//!   original header is reused, the trailer recomputed, and leftover space zero-filled.
//!
//! [`pack`] only plans: it returns the new stream bytes as patches, each already checked
//! to decode to the edited data, so memory use scales with the edits rather than the
//! file. [`PackResult::write_to`] streams the output and [`PackResult::verify_output`]
//! decodes every stream from the file as written.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use rayon::prelude::*;
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

/// New bytes for one stream slot.
#[derive(Debug, Clone)]
struct Patch {
    offset: usize,
    bytes: Vec<u8>,
    /// Zero-fill from the end of `bytes` up to here (the original stream end).
    clear_to: usize,
}

#[derive(Debug)]
pub struct PackResult {
    /// One entry per manifest stream, in offset order.
    pub streams: Vec<StreamPlan>,
    /// In offset order. Empty unless every stream fits.
    patches: Vec<Patch>,
    input_len: usize,
    /// The manifest for the packed output, minus its source size/CRC (known once written).
    manifest: Manifest,
}

impl PackResult {
    /// True if every stream fits, so output can be written.
    pub fn fits(&self) -> bool {
        self.failures().next().is_none()
    }

    pub fn failures(&self) -> impl Iterator<Item = &StreamPlan> {
        self.streams.iter().filter(|s| matches!(s.outcome, Outcome::TooLarge { .. }))
    }

    pub fn repacked(&self) -> impl Iterator<Item = &StreamPlan> {
        self.streams.iter().filter(|s| matches!(s.outcome, Outcome::Repacked { .. }))
    }

    /// Stream the packed file to `w`: the input with each patch applied. The output is
    /// always the same length as the input. `input` must be the data given to [`pack`].
    pub fn write_to(&self, input: &[u8], mut w: impl Write) -> io::Result<()> {
        assert!(self.fits(), "write_to called on a pack result with streams that don't fit");
        assert_eq!(input.len(), self.input_len, "write_to needs the same input that was packed");
        let mut pos = 0;
        for patch in &self.patches {
            w.write_all(&input[pos..patch.offset])?;
            w.write_all(&patch.bytes)?;
            let written_to = patch.offset + patch.bytes.len();
            if written_to < patch.clear_to {
                io::copy(&mut io::repeat(0).take((patch.clear_to - written_to) as u64), &mut w)?;
            }
            pos = written_to.max(patch.clear_to);
        }
        w.write_all(&input[pos..])?;
        w.flush()
    }

    /// The packed file in memory, or `None` if a stream didn't fit.
    pub fn apply(&self, input: &[u8]) -> Option<Vec<u8>> {
        self.fits().then(|| {
            let mut out = Vec::with_capacity(input.len());
            self.write_to(input, &mut out).expect("writing to a Vec cannot fail");
            out
        })
    }

    /// Decode every stream from the written `output` and check it against the plan:
    /// unchanged streams must still match the original manifest, repacked ones must
    /// decode to exactly the edited data. Returns the manifest for the output, so it
    /// can be extracted and packed again. Its `source.path` is copied from the input
    /// manifest; callers should update it.
    pub fn verify_output(&self, output: &[u8]) -> Result<Manifest> {
        let largest = self.manifest.streams.iter().map(|s| s.decompressed_size).max().unwrap_or(0);
        let max_output = usize::try_from(largest).unwrap_or(usize::MAX);
        self.manifest
            .streams
            .par_iter()
            .map_init(
                || DecodeCtx::new(max_output),
                |ctx, entry| {
                    decode_stream(output, entry, ctx).map(|_| ()).map_err(|e| Error::Verify {
                        id: entry.id,
                        offset: entry.offset,
                        reason: e.to_string(),
                    })
                },
            )
            .collect::<Result<()>>()?;
        let mut manifest = self.manifest.clone();
        manifest.source.size = output.len() as u64;
        manifest.source.crc32 = crc32(output);
        Ok(manifest)
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

/// Plan the packed file from `data`, the `manifest` it was scanned with, and new
/// contents for some streams (keyed by stream id). Edited streams are compressed in
/// parallel, and each new stream is decoded again to confirm it holds the edited data.
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
    let max_output = usize::try_from(largest).unwrap_or(usize::MAX);

    let planned: Vec<(StreamPlan, Option<Patch>)> = streams
        .par_iter()
        .enumerate()
        .map_init(
            || DecodeCtx::new(max_output),
            |ctx, (i, entry)| {
                let next_start = streams.get(i + 1).map_or(data.len(), |s| s.offset as usize);
                plan_stream(data, entry, edits.get(&entry.id), next_start, opts, ctx)
            },
        )
        .collect::<Result<_>>()?;

    let (plans, patches): (Vec<StreamPlan>, Vec<Option<Patch>>) = planned.into_iter().unzip();
    let fits = plans.iter().all(|p| !matches!(p.outcome, Outcome::TooLarge { .. }));
    let patches = if fits { patches.into_iter().flatten().collect() } else { Vec::new() };
    let manifest = packed_manifest(manifest, &plans, edits);
    Ok(PackResult { streams: plans, patches, input_len: data.len(), manifest })
}

fn plan_stream(
    data: &[u8],
    entry: &StreamEntry,
    edit: Option<&Vec<u8>>,
    next_start: usize,
    opts: &PackOptions,
    ctx: &mut DecodeCtx,
) -> Result<(StreamPlan, Option<Patch>)> {
    let mut plan = StreamPlan {
        id: entry.id,
        offset: entry.offset,
        format: entry.format,
        original_size: entry.compressed_size,
        outcome: Outcome::Unchanged,
    };
    let Some(new_data) = edit else { return Ok((plan, None)) };

    // Decoding the original confirms it is still intact and locates its header.
    let original = decode_stream(data, entry, ctx)?;
    let start = entry.offset as usize;
    let end = entry.end() as usize;
    let header = &data[start..start + original.body.start];
    let slack = if opts.use_zero_slack { data[end..next_start].iter().take_while(|&&b| b == 0).count() } else { 0 };
    let available = end - start + slack;

    let codec = codec_for(entry.format);
    let first = first_params(entry, &original)?;
    let (stream, params) = fit(codec, header, new_data, first, available);
    if stream.len() > available {
        plan.outcome = Outcome::TooLarge { best_size: stream.len() as u64, available: available as u64 };
        return Ok((plan, None));
    }

    // The new stream must decode, alone, to exactly the edited data.
    let fail = |reason: String| Error::Verify { id: entry.id, offset: entry.offset, reason };
    let decoded = codec.decode(&stream, ctx).map_err(|e| fail(format!("{} decode failed: {e}", entry.format)))?;
    if decoded.compressed_size != stream.len() || decoded.data != *new_data {
        return Err(fail("re-encoded stream does not decode to the edited data".into()));
    }

    plan.outcome = Outcome::Repacked {
        new_size: stream.len() as u64,
        params,
        reused_original_params: entry.params.exact_match && params == first,
        slack_used: (start + stream.len()).saturating_sub(end) as u64,
    };
    Ok((plan, Some(Patch { offset: start, bytes: stream, clear_to: end })))
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

fn packed_manifest(original: &Manifest, plans: &[StreamPlan], edits: &BTreeMap<u32, Vec<u8>>) -> Manifest {
    let mut manifest = original.clone();
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
