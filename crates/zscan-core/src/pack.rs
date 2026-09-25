//! Reinjecting edited streams (the packzip replacement).
//!
//! For each stream in the manifest:
//! - No edit: the original bytes are kept untouched.
//! - Edited: the new data is encoded with the settings matched at scan time (or defaults
//!   taken from the original header), then with stronger settings if that doesn't fit
//!   the original slot. Header fields are reused where the format allows, and leftover
//!   space is zero-filled. If it still doesn't fit, it may grow into zero slack after it
//!   (opt-in), or, if the stream has an offset field and relocation is enabled, move to
//!   the end of the file, leaving its old slot zeroed.
//!
//! Length fields ([`crate::fields`]) are checked before anything is planned and
//! rewritten to the new sizes and offsets.
//!
//! [`pack`] only plans: it returns the changes as patches, each new stream already
//! checked to decode to the edited data, so memory use scales with the edits rather
//! than the file. [`PackResult::write_to`] streams the output and
//! [`PackResult::verify_output`] decodes every stream and rechecks every field in the
//! file as written.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use rayon::prelude::*;
use serde::Serialize;

use crate::checksum::crc32;
use crate::codec::{Codec, DecodeCtx, Decoded, Format, SizeHint, codec_for};
use crate::error::{Error, Result, io_err};
use crate::extract::decode_stream;
use crate::fields::{check_fields, measure, measure_name};
use crate::manifest::{Manifest, Measures, StreamEntry, is_safe_filename};
use crate::output::write_via_temp;
use crate::params::EncoderParams;

#[derive(Debug, Clone)]
pub struct PackOptions {
    /// Refuse to run if the input's size or CRC-32 differs from the manifest.
    pub verify_source: bool,
    /// Let a stream grow into the zero bytes that follow it (never past the next stream).
    /// Only safe when whatever reads the file finds the stream's end by decoding it, or
    /// reads its size from a length field.
    pub use_zero_slack: bool,
    /// Move a stream that doesn't fit to the end of the file, if it has offset and
    /// compressed-size fields and no field just in front of it (a local header, which
    /// would be left behind). The file grows.
    pub relocate: bool,
    /// Alignment for relocated streams (1 = none).
    pub align: u64,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self { verify_source: true, use_zero_slack: false, relocate: false, align: 1 }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// No edit; original bytes kept.
    Unchanged,
    Repacked {
        new_size: u64,
        params: EncoderParams,
        /// True when the settings that reproduce the original stream were good enough.
        reused_original_params: bool,
        /// Bytes of trailing zero slack the new stream grew into.
        slack_used: u64,
        /// Where the stream moved to, if it didn't fit in place.
        #[serde(skip_serializing_if = "Option::is_none")]
        relocated_to: Option<u64>,
    },
    /// Even the strongest settings tried don't fit.
    TooLarge {
        best_size: u64,
        available: u64,
        /// The stream has offset and compressed-size fields and no local header, so
        /// relocation would work.
        relocatable: bool,
    },
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

/// A length field whose value pack changes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldUpdate {
    pub stream_id: u32,
    pub offset: u64,
    pub measures: Measures,
    pub old: u64,
    pub new: u64,
}

/// New bytes at one place in the output.
#[derive(Debug, Clone)]
struct Patch {
    offset: usize,
    bytes: Vec<u8>,
    /// Zero-fill from the end of `bytes` up to here.
    clear_to: usize,
}

impl Patch {
    fn end(&self) -> usize {
        (self.offset + self.bytes.len()).max(self.clear_to)
    }
}

#[derive(Debug)]
pub struct PackResult {
    /// One entry per manifest stream, in offset order.
    pub streams: Vec<StreamPlan>,
    /// Length fields that change, in offset order. Empty unless every stream fits.
    pub field_updates: Vec<FieldUpdate>,
    /// In offset order, non-overlapping. Empty unless every stream fits.
    patches: Vec<Patch>,
    input_len: usize,
    output_len: usize,
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

    /// Size of the packed file: the input's, unless streams were relocated.
    pub fn output_len(&self) -> u64 {
        self.output_len as u64
    }

    /// Stream the packed file to `w`: the input with each patch applied, then any
    /// relocated streams. `input` must be the data given to [`pack`].
    pub fn write_to(&self, input: &[u8], mut w: impl Write) -> io::Result<()> {
        assert!(self.fits(), "write_to called on a pack result with streams that don't fit");
        assert_eq!(input.len(), self.input_len, "write_to needs the same input that was packed");
        let copy = |w: &mut dyn Write, from: usize, to: usize| -> io::Result<()> {
            if from >= to {
                return Ok(());
            }
            let split = to.min(input.len()).max(from);
            w.write_all(&input[from..split])?;
            io::copy(&mut io::repeat(0).take((to - split) as u64), w).map(|_| ())
        };
        let mut pos = 0;
        for patch in &self.patches {
            copy(&mut w, pos, patch.offset)?;
            w.write_all(&patch.bytes)?;
            let written_to = patch.offset + patch.bytes.len();
            io::copy(&mut io::repeat(0).take(patch.clear_to.saturating_sub(written_to) as u64), &mut w)?;
            pos = patch.end();
        }
        copy(&mut w, pos, self.output_len)?;
        w.flush()
    }

    /// Write the packed file to `path`, read it back and [verify](Self::verify_output)
    /// it, and only then move it into place. Returns the manifest for the output, with
    /// `source.path` set to `path`.
    pub fn write_file(&self, input: &[u8], path: &Path) -> Result<Manifest> {
        let mut manifest = write_via_temp(path, |tmp| {
            let file = fs::File::create(tmp).map_err(io_err(tmp))?;
            self.write_to(input, io::BufWriter::with_capacity(8 << 20, file)).map_err(io_err(tmp))?;
            self.verify_output(&crate::input::open(tmp)?)
        })?;
        manifest.source.path = path.display().to_string();
        Ok(manifest)
    }

    /// The packed file in memory, or `None` if a stream didn't fit.
    pub fn apply(&self, input: &[u8]) -> Option<Vec<u8>> {
        self.fits().then(|| {
            let mut out = Vec::with_capacity(self.output_len);
            self.write_to(input, &mut out).expect("writing to a Vec cannot fail");
            out
        })
    }

    /// Check the written `output` against the plan: every stream decodes to its intended
    /// data (unchanged ones to the original, repacked ones to the edit) at its new
    /// offset, and every length field holds its new value. Returns the manifest for the
    /// output, so it can be extracted and packed again. Its `source.path` is copied from
    /// the input manifest; callers should update it.
    pub fn verify_output(&self, output: &[u8]) -> Result<Manifest> {
        if output.len() != self.output_len {
            return Err(Error::Verify {
                id: 0,
                offset: 0,
                reason: format!("output is {} bytes, expected {}", output.len(), self.output_len),
            });
        }
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
        check_fields(output, &self.manifest)
            .map_err(|e| Error::Verify { id: 0, offset: 0, reason: format!("length fields: {e}") })?;
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

/// A new stream and whether it has to move.
struct Encoded {
    bytes: Vec<u8>,
    relocate: bool,
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
    // Wrong rules would corrupt the file, so they must describe it exactly.
    check_fields(data, manifest)?;
    let align = opts.align.max(1) as usize;

    let largest = streams
        .iter()
        .map(|s| s.decompressed_size)
        .chain(edits.values().map(|v| v.len() as u64))
        .max()
        .unwrap_or(0);
    let max_output = usize::try_from(largest).unwrap_or(usize::MAX);

    let planned: Vec<(StreamPlan, Option<Encoded>)> = streams
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

    let mut plans = Vec::with_capacity(planned.len());
    let mut patches = Vec::new();
    let mut output_len = data.len();
    for (mut plan, encoded) in planned {
        if let Some(Encoded { bytes, relocate }) = encoded {
            let start = plan.offset as usize;
            let end = start + plan.original_size as usize;
            if relocate {
                let new_offset = output_len.next_multiple_of(align);
                output_len = new_offset + bytes.len();
                if let Outcome::Repacked { relocated_to, .. } = &mut plan.outcome {
                    *relocated_to = Some(new_offset as u64);
                }
                patches.push(Patch { offset: start, bytes: Vec::new(), clear_to: end });
                patches.push(Patch { offset: new_offset, bytes, clear_to: 0 });
            } else {
                patches.push(Patch { offset: start, bytes, clear_to: end });
            }
        }
        plans.push(plan);
    }

    let fits = plans.iter().all(|p| !matches!(p.outcome, Outcome::TooLarge { .. }));
    let packed = packed_manifest(manifest, &plans, edits);
    let mut field_updates = Vec::new();
    if fits {
        for entry in &packed.streams {
            for f in &entry.length_fields {
                let new = measure(entry, f.measures);
                let bytes = f.encode(new).ok_or_else(|| {
                    Error::Pack(format!(
                        "stream {}: its new {} ({new}) doesn't fit the {}-byte field at {:#x}",
                        entry.id,
                        measure_name(f.measures),
                        f.width,
                        f.offset
                    ))
                })?;
                let old = f.read(data).expect("checked by check_fields");
                if f.stored_value(new) != Some(old) {
                    field_updates.push(FieldUpdate { stream_id: entry.id, offset: f.offset, measures: f.measures, old, new: f.stored_value(new).unwrap() });
                    patches.push(Patch { offset: f.offset as usize, bytes, clear_to: 0 });
                }
            }
        }
    } else {
        patches.clear();
        output_len = data.len();
    }
    patches.sort_by_key(|p| p.offset);
    field_updates.sort_by_key(|u| u.offset);
    if let Some(w) = patches.windows(2).find(|w| w[0].end() > w[1].offset) {
        return Err(Error::Pack(format!("internal error: changes at {:#x} and {:#x} overlap", w[0].offset, w[1].offset)));
    }
    Ok(PackResult { streams: plans, field_updates, patches, input_len: data.len(), output_len, manifest: packed })
}

fn plan_stream(
    data: &[u8],
    entry: &StreamEntry,
    edit: Option<&Vec<u8>>,
    next_start: usize,
    opts: &PackOptions,
    ctx: &mut DecodeCtx,
) -> Result<(StreamPlan, Option<Encoded>)> {
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
    let old_stream = &data[start..end];
    let slack = if opts.use_zero_slack { data[end..next_start].iter().take_while(|&&b| b == 0).count() } else { 0 };
    let available = end - start + slack;

    let codec = codec_for(entry.format)?;
    let first = match &entry.exact_params {
        Some(p) => codec
            .adapt_params(old_stream, &original, p)
            .map_err(|e| Error::InvalidManifest(format!("stream {}: {e}", entry.id)))?,
        None => codec.default_params(old_stream, &original),
    };
    let (stream, params) = fit(codec, old_stream, &original, new_data, &first, available)
        .map_err(|e| Error::Stream { id: entry.id, offset: entry.offset, reason: e })?;
    let relocatable = can_relocate(entry);
    let relocate = stream.len() > available;
    if relocate && !(opts.relocate && relocatable) {
        plan.outcome = Outcome::TooLarge { best_size: stream.len() as u64, available: available as u64, relocatable };
        return Ok((plan, None));
    }

    // The new stream must decode, alone, to exactly the edited data.
    let fail = |reason: String| Error::Verify { id: entry.id, offset: entry.offset, reason };
    let hint = SizeHint::exact(stream.len(), new_data.len());
    let decoded =
        codec.decode_with_hint(&stream, hint, ctx).map_err(|e| fail(format!("{} decode failed: {e}", entry.format)))?;
    if decoded.compressed_size != stream.len() || decoded.data != *new_data {
        return Err(fail("re-encoded stream does not decode to the edited data".into()));
    }

    plan.outcome = Outcome::Repacked {
        new_size: stream.len() as u64,
        reused_original_params: entry.exact_params.is_some() && params == first,
        params,
        slack_used: if relocate { 0 } else { (start + stream.len()).saturating_sub(end) as u64 },
        relocated_to: None, // assigned once every stream is planned
    };
    Ok((plan, Some(Encoded { bytes: stream, relocate })))
}

/// A stream can move if fields record both where it is and how long it is (a reader
/// can't otherwise find it, or would read the old length), and no field sits right in
/// front of it: that would be a local header, which a reader expects just before the
/// data but which relocation leaves behind.
fn can_relocate(entry: &StreamEntry) -> bool {
    const LOCAL_HEADER: u64 = 16;
    let has = |m: Measures| entry.length_fields.iter().any(|f| f.measures == m);
    let local_header = entry.length_fields.iter().any(|f| f.end() <= entry.offset && f.end() + LOCAL_HEADER > entry.offset);
    has(Measures::Offset) && has(Measures::Compressed) && !local_header
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
    if let Some(last) = streams.last()
        && last.end() > len as u64
    {
        return Err(Error::InvalidManifest(format!("stream {} runs past the end of the input", last.id)));
    }
    Ok(streams)
}

/// Encode with `first` (the scan's exact match, or defaults from the original header);
/// if that doesn't fit in `available` bytes, also try the codec's stronger settings and
/// keep the smallest result.
fn fit(
    codec: &dyn Codec,
    old_stream: &[u8],
    original: &Decoded,
    data: &[u8],
    first: &EncoderParams,
    available: usize,
) -> std::result::Result<(Vec<u8>, EncoderParams), String> {
    let build = |p: &EncoderParams| codec.encode(old_stream, original, data, p);
    let mut best = (build(first)?, first.clone());
    if best.0.len() <= available {
        return Ok(best);
    }
    for p in codec.stronger_params(first) {
        let stream = build(&p)?;
        if stream.len() < best.0.len() {
            best = (stream, p);
        }
    }
    Ok(best)
}

fn packed_manifest(original: &Manifest, plans: &[StreamPlan], edits: &BTreeMap<u32, Vec<u8>>) -> Manifest {
    let mut manifest = original.clone();
    for entry in &mut manifest.streams {
        let Some(plan) = plans.iter().find(|p| p.id == entry.id) else { continue };
        if let Outcome::Repacked { new_size, params, relocated_to, .. } = &plan.outcome {
            let new_data = &edits[&entry.id];
            entry.compressed_size = *new_size;
            entry.decompressed_size = new_data.len() as u64;
            entry.crc32 = crc32(new_data);
            // The new stream was made with exactly these settings.
            entry.exact_params = Some(params.clone());
            if let Some(offset) = relocated_to {
                entry.offset = *offset;
            }
        }
    }
    manifest.streams.sort_by_key(|s| s.offset);
    manifest
}
