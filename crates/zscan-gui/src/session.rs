//! Everything the GUI knows, without any drawing code: the open file, its manifest, the
//! edits, and the results of the last operations.
//!
//! Slow work (opening, scanning, packing) is done by the free functions here, on a
//! worker thread started by [`crate::jobs`]; their results are applied to the
//! [`Session`] on the UI thread. Tests drive the same functions directly.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use rayon::prelude::*;
use zscan_core::content::{ContentType, sniff};
use zscan_core::entropy::{EntropyBlock, entropy_map};
use zscan_core::input::{self, Input};
use zscan_core::{
    DecodeCtx, DetectOptions, FieldUpdate, Manifest, PackOptions, PackResult, Progress, ScanOptions, ScanStats,
    SourceInfo, StreamEntry, StreamPlan, apply_unambiguous, decode_stream, detect_fields, pack, scan_with_progress,
};

use crate::project::Project;

/// Blocks in the entropy map: enough for a sharp picture at any window width.
pub const ENTROPY_BLOCKS: usize = 4096;
/// Bytes of decompressed data looked at to guess a stream's content type.
const SNIFF_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub level: Level,
    pub text: String,
}

/// A file open for reading (memory-mapped; never written to).
pub struct OpenFile {
    pub path: PathBuf,
    pub data: Arc<Input>,
    pub entropy: Vec<EntropyBlock>,
}

impl OpenFile {
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// A manifest ready to use with an open file.
pub struct Loaded {
    pub manifest: Manifest,
    pub content: HashMap<u32, ContentType>,
    /// Why the manifest doesn't describe the file, if it doesn't.
    pub mismatch: Option<String>,
}

/// What the last pack did or would do.
#[derive(Debug, Clone)]
pub struct PackReport {
    pub streams: Vec<StreamPlan>,
    pub field_updates: Vec<FieldUpdate>,
    pub input_len: u64,
    pub output_len: u64,
    pub fits: bool,
    /// Where the packed file was written and verified, or `None` for a dry run.
    pub written: Option<PathBuf>,
}

impl PackReport {
    fn new(result: &PackResult, input_len: u64, written: Option<PathBuf>) -> Self {
        Self {
            streams: result.streams.clone(),
            field_updates: result.field_updates.clone(),
            input_len,
            output_len: result.output_len(),
            fits: result.fits(),
            written,
        }
    }
}

#[derive(Default)]
pub struct Session {
    pub file: Option<OpenFile>,
    pub manifest: Option<Manifest>,
    /// Stream id -> file holding its new decompressed contents. Files are read when
    /// packing, so they can still be edited after being chosen.
    pub edits: BTreeMap<u32, PathBuf>,
    /// Guessed content type of each stream, by id.
    pub content: HashMap<u32, ContentType>,
    pub scan_options: ScanOptions,
    pub project_path: Option<PathBuf>,
    /// Changes to the manifest or edits not yet saved to a project.
    pub dirty: bool,
    /// Why the manifest doesn't describe the open file, if it doesn't.
    pub source_mismatch: Option<String>,
    pub last_scan: Option<ScanStats>,
    pub last_pack: Option<PackReport>,
    pub log: Vec<LogLine>,
    /// A stream the UI should select and scroll to (set when a job adds or finds one).
    pub select: Option<u32>,
    /// Bumped whenever the manifest or edits change, so views can cache.
    pub generation: u64,
}

impl Session {
    pub fn info(&mut self, text: impl Into<String>) {
        self.log.push(LogLine { level: Level::Info, text: text.into() });
    }

    pub fn warn(&mut self, text: impl Into<String>) {
        self.log.push(LogLine { level: Level::Warn, text: text.into() });
    }

    pub fn error(&mut self, text: impl Into<String>) {
        self.log.push(LogLine { level: Level::Error, text: text.into() });
    }

    fn changed(&mut self) {
        self.dirty = true;
        self.generation += 1;
    }

    pub fn stream(&self, id: u32) -> Option<&StreamEntry> {
        self.manifest.as_ref()?.streams.iter().find(|s| s.id == id)
    }

    pub fn streams(&self) -> &[StreamEntry] {
        self.manifest.as_ref().map_or(&[], |m| &m.streams)
    }

    /// A newly opened file, with no manifest yet.
    pub fn set_file(&mut self, file: OpenFile) {
        self.info(format!("opened {} ({} bytes)", file.path.display(), file.len()));
        *self = Session {
            file: Some(file),
            scan_options: std::mem::take(&mut self.scan_options),
            log: std::mem::take(&mut self.log),
            generation: self.generation + 1,
            ..Session::default()
        };
    }

    /// Close the file and forget everything about it.
    pub fn close(&mut self) {
        let generation = self.generation + 1;
        *self = Session {
            scan_options: std::mem::take(&mut self.scan_options),
            log: std::mem::take(&mut self.log),
            generation,
            ..Session::default()
        };
    }

    /// A fresh manifest from a scan. Edits referred to the old stream ids, so they go.
    pub fn set_scanned(&mut self, scanned: Loaded, stats: ScanStats) {
        let n = scanned.manifest.streams.len();
        if !self.edits.is_empty() {
            self.warn(format!("{} edit(s) dropped: the new scan renumbers the streams", self.edits.len()));
        }
        self.info(format!("scan found {n} stream(s) in {:.2} s", stats.total().as_secs_f64()));
        self.last_scan = Some(stats);
        self.set_manifest(scanned, BTreeMap::new());
    }

    /// Use `loaded` with the open file, along with `edits` (from a project).
    pub fn set_manifest(&mut self, loaded: Loaded, edits: BTreeMap<u32, PathBuf>) {
        if let Some(why) = &loaded.mismatch {
            self.warn(format!("the manifest doesn't match this file ({why}); packing is disabled"));
        }
        self.manifest = Some(loaded.manifest);
        self.content = loaded.content;
        self.source_mismatch = loaded.mismatch;
        self.edits = edits;
        self.last_pack = None;
        self.changed();
    }

    /// Replace a stream's contents with the file at `path`.
    pub fn set_edit(&mut self, id: u32, path: PathBuf) {
        self.info(format!("stream {id} will be replaced by {}", path.display()));
        self.edits.insert(id, path);
        self.last_pack = None;
        self.changed();
    }

    pub fn revert(&mut self, id: u32) {
        if self.edits.remove(&id).is_some() {
            self.info(format!("stream {id}: edit removed"));
            self.last_pack = None;
            self.changed();
        }
    }

    /// Edits found in an extract directory (files that differ from the originals).
    pub fn set_edits_from_dir(&mut self, dir: &Path, ids: Vec<u32>) {
        let Some(manifest) = &self.manifest else { return };
        let files: Vec<(u32, PathBuf)> =
            manifest.streams.iter().filter(|s| ids.contains(&s.id)).map(|s| (s.id, dir.join(&s.file))).collect();
        self.info(format!("{} edited file(s) found in {}", files.len(), dir.display()));
        self.edits.extend(files);
        self.last_pack = None;
        self.changed();
    }

    pub fn add_stream(&mut self, found: zscan_core::FoundStream, content: Option<ContentType>) -> Result<u32> {
        let manifest = self.manifest.as_mut().context("scan the file or load a manifest first")?;
        let (format, offset) = (found.format, found.offset);
        let id = manifest.add_stream(found)?;
        if let Some(c) = content {
            self.content.insert(id, c);
        }
        self.info(format!("added {format} stream at {offset:#x} as stream {id}"));
        self.select = Some(id);
        self.changed();
        Ok(id)
    }

    pub fn set_fields(&mut self, manifest: Manifest, candidates: usize, added: usize) {
        self.manifest = Some(manifest);
        self.info(format!("{candidates} length-field candidate(s), {added} unambiguous one(s) added"));
        self.changed();
    }

    pub fn set_pack_report(&mut self, report: PackReport) {
        match (&report.written, report.fits) {
            (Some(path), _) => self.info(format!("packed to {} (every stream verified)", path.display())),
            (None, true) => self.info("dry run: every edited stream fits and decodes correctly"),
            (None, false) => {
                let n = report.streams.iter().filter(|s| matches!(s.outcome, zscan_core::Outcome::TooLarge { .. })).count();
                self.warn(format!("{n} stream(s) don't fit"));
            }
        }
        self.last_pack = Some(report);
    }

    pub fn to_project(&self) -> Option<Project> {
        Some(Project {
            input: self.file.as_ref()?.path.clone(),
            manifest: self.manifest.clone()?,
            edits: self.edits.clone(),
        })
    }

    pub fn saved_project(&mut self, path: PathBuf) {
        self.info(format!("project saved to {}", path.display()));
        self.project_path = Some(path);
        self.dirty = false;
    }
}

/// Read every edit file, for [`run_pack`].
pub fn read_edits(edits: &BTreeMap<u32, PathBuf>) -> Result<BTreeMap<u32, Vec<u8>>> {
    edits
        .iter()
        .map(|(&id, path)| Ok((id, std::fs::read(path).with_context(|| format!("stream {id}: {}", path.display()))?)))
        .collect()
}

pub fn open_file(path: &Path) -> Result<OpenFile> {
    let data = input::open(path)?;
    let blocks = ENTROPY_BLOCKS.min(data.len().div_ceil(256));
    let entropy = entropy_map(&data, blocks);
    Ok(OpenFile { path: path.to_path_buf(), data: Arc::new(data), entropy })
}

/// Decode every stream and guess what it holds. Streams that fail to decode are left out.
pub fn analyse(data: &[u8], manifest: &Manifest) -> HashMap<u32, ContentType> {
    let largest = manifest.streams.iter().map(|s| s.decompressed_size).max().unwrap_or(0);
    let max_output = usize::try_from(largest).unwrap_or(usize::MAX);
    manifest
        .streams
        .par_iter()
        .map_init(
            || DecodeCtx::new(max_output),
            |ctx, s| {
                let decoded = decode_stream(data, s, ctx).ok()?;
                Some((s.id, sniff(&decoded.data[..decoded.data.len().min(SNIFF_BYTES)])))
            },
        )
        .flatten()
        .collect()
}

pub fn run_scan(file: &OpenFile, opts: ScanOptions, progress: &Progress) -> Result<(Loaded, ScanStats)> {
    let (found, stats) = scan_with_progress(&file.data, &opts, progress)?;
    let manifest = Manifest::new(SourceInfo::describe(&file.path, &file.data), opts, found);
    let content = analyse(&file.data, &manifest);
    Ok((Loaded { manifest, content, mismatch: None }, stats))
}

/// Check a manifest against the open file and analyse its streams.
pub fn prepare_manifest(file: &OpenFile, manifest: Manifest) -> Loaded {
    let mismatch = manifest.source.check(&file.data).err().map(|e| e.to_string());
    let content = if mismatch.is_none() { analyse(&file.data, &manifest) } else { HashMap::new() };
    Loaded { manifest, content, mismatch }
}

/// Open a project's input and check its manifest. Relative paths were already resolved.
pub fn open_project(project: Project) -> Result<(OpenFile, Loaded, BTreeMap<u32, PathBuf>)> {
    let file = open_file(&project.input).with_context(|| "the project's input file")?;
    let loaded = prepare_manifest(&file, project.manifest);
    Ok((file, loaded, project.edits))
}

/// Pack with the session's edits. With `output`, also write the file (verified).
pub fn run_pack(
    data: &[u8],
    manifest: &Manifest,
    edits: &BTreeMap<u32, Vec<u8>>,
    opts: &PackOptions,
    output: Option<&Path>,
) -> Result<(PackReport, Option<Manifest>)> {
    let result = pack(data, manifest, edits, opts)?;
    let mut packed_manifest = None;
    let written = match output {
        Some(path) if result.fits() => {
            packed_manifest = Some(result.write_file(data, path)?);
            Some(path.to_path_buf())
        }
        _ => None,
    };
    Ok((PackReport::new(&result, data.len() as u64, written), packed_manifest))
}

/// Detect length fields and add the unambiguous ones to a copy of `manifest`.
pub fn run_fields(data: &[u8], manifest: &Manifest) -> Result<(Manifest, usize, usize)> {
    manifest.source.check(data)?;
    let candidates = detect_fields(data, manifest, &DetectOptions::default());
    let mut updated = manifest.clone();
    let added = apply_unambiguous(&mut updated, &candidates);
    zscan_core::check_fields(data, &updated)?;
    Ok((updated, candidates.len(), added.len()))
}

/// Decompressed contents of stream `id`, or of its edit if it has one and `edited`.
pub fn stream_contents(data: &[u8], entry: &StreamEntry, edit: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(path) = edit {
        return std::fs::read(path).with_context(|| path.display().to_string());
    }
    let mut ctx = DecodeCtx::new(usize::try_from(entry.decompressed_size).unwrap_or(usize::MAX));
    Ok(decode_stream(data, entry, &mut ctx)?.data)
}

/// `dir/name.ext` -> `dir/name.packed.ext`
pub fn default_packed_path(input: &Path) -> PathBuf {
    let stem = input.file_stem().map_or("output".into(), |s| s.to_string_lossy());
    let name = match input.extension() {
        Some(ext) => format!("{stem}.packed.{}", ext.to_string_lossy()),
        None => format!("{stem}.packed"),
    };
    input.with_file_name(name)
}

/// Error unless `output` is a different file from `input`.
pub fn check_not_input(output: &Path, input: &Path) -> Result<()> {
    let same = matches!((output.canonicalize(), input.canonicalize()), (Ok(a), Ok(b)) if a == b);
    if same {
        bail!("refusing to overwrite the input file; choose another name");
    }
    Ok(())
}
