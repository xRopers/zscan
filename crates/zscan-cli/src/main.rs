use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use zscan_core::entropy::{entropy_map, shannon};
use zscan_core::scan::{DEFAULT_MAX_OUTPUT, DEFAULT_MIN_SIZE, DEFAULT_RAW_MAX_ENTROPY, DEFAULT_RAW_MIN_COMPRESSED, DEFAULT_RAW_MIN_RATIO};
use zscan_core::{
    DetectOptions, ExtractOptions, FieldCandidate, FieldUpdate, Format, Manifest, Outcome, PackOptions, PackResult,
    RebuildSummary, ScanOptions, apply_unambiguous, check_fields, detect_fields, rebuild, unpack, ScanStats, SourceInfo, StreamEntry,
    StreamPlan, decode_at, extract_all, input, load_edits, pack, scan, scan_with_stats,
};

#[derive(Parser)]
#[command(name = "zscan", version, about = "Find, extract and reinject compressed streams inside binary files")]
struct Cli {
    /// Print machine-readable JSON on stdout instead of text
    #[arg(long, global = true)]
    json: bool,

    /// Worker threads [default: one per CPU]
    #[arg(short = 'j', long, global = true, value_name = "N")]
    threads: Option<usize>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find compressed streams and optionally write a manifest
    Scan {
        file: PathBuf,
        /// Write the manifest here
        #[arg(short, long, value_name = "MANIFEST")]
        output: Option<PathBuf>,
        /// Print time spent per scan phase to stderr
        #[arg(long)]
        stats: bool,
        #[command(flatten)]
        filters: ScanArgs,
    },
    /// Extract streams listed in a manifest (or found by a fresh scan if no manifest is given)
    Extract {
        file: PathBuf,
        /// Manifest from `zscan scan -o`
        #[arg(short, long)]
        manifest: Option<PathBuf>,
        /// Output directory
        #[arg(short = 'd', long = "dir", value_name = "DIR")]
        dir: PathBuf,
        /// Extract even if the input's size or CRC no longer matches the manifest
        #[arg(long)]
        force: bool,
        /// Filters for the fresh scan (ignored with --manifest)
        #[command(flatten)]
        filters: ScanArgs,
    },
    /// Reinject edited files from an extract directory into a copy of the input
    Pack {
        file: PathBuf,
        /// Manifest from `zscan scan -o`
        #[arg(short, long)]
        manifest: PathBuf,
        /// Directory with the extracted (and edited) files
        #[arg(short = 'd', long = "dir", value_name = "DIR")]
        dir: PathBuf,
        /// Output file [default: <input stem>.packed.<ext> next to the input]
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Show per-stream results without writing anything
        #[arg(long)]
        dry_run: bool,
        /// Also write a manifest describing the packed file
        #[arg(long, value_name = "MANIFEST")]
        manifest_out: Option<PathBuf>,
        /// Let a stream grow into zero bytes that follow it. Only safe if whatever reads
        /// the file finds the stream's end by decoding it, or reads its size from a
        /// length field in the manifest
        #[arg(long)]
        use_slack: bool,
        /// Move a stream that doesn't fit to the end of the file (which grows), if the
        /// manifest lists offset and compressed-size fields for it
        #[arg(long)]
        relocate: bool,
        /// Alignment for relocated streams
        #[arg(long, default_value_t = 1, value_parser = parse_offset)]
        align: u64,
        /// Pack even if the input's size or CRC no longer matches the manifest
        #[arg(long)]
        force: bool,
    },
    /// Find fields that record each stream's sizes or offset (size prefixes, archive
    /// directories); `--apply` adds the unambiguous ones to the manifest so pack keeps them
    /// up to date
    Fields {
        file: PathBuf,
        /// Manifest from `zscan scan -o`
        #[arg(short, long)]
        manifest: PathBuf,
        /// Bytes before each stream searched for size fields of any value
        #[arg(long, default_value_t = 64)]
        window: u64,
        /// Elsewhere in the file, only look for values at least this large
        #[arg(long, default_value_t = 65_536)]
        min_value: u64,
        /// Add unambiguous candidates to the manifest
        #[arg(long)]
        apply: bool,
    },
    /// Expand a file into its streams' decompressed contents plus everything needed to
    /// recreate it bit for bit (to store or compress it better); undo with `rebuild`
    Unpack {
        file: PathBuf,
        /// Directory to create (must not exist or be empty)
        #[arg(short = 'd', long = "dir", value_name = "DIR")]
        dir: PathBuf,
        /// Manifest from `zscan scan -o` (otherwise the file is scanned first)
        #[arg(short, long)]
        manifest: Option<PathBuf>,
        /// Filters for the scan (ignored with --manifest)
        #[command(flatten)]
        filters: ScanArgs,
    },
    /// Recreate the original file, bit for bit, from an `unpack` directory
    Rebuild {
        /// Directory written by `zscan unpack`
        dir: PathBuf,
        /// File to write
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Try decoding one format at an exact offset, and optionally add the stream to a
    /// manifest. For formats that can't be scanned for (brotli), or to check a location
    Try {
        file: PathBuf,
        /// Offset of the stream start (decimal, or hex with 0x)
        #[arg(long, value_name = "OFFSET", value_parser = parse_offset)]
        at: u64,
        /// Format to decode as
        #[arg(long)]
        format: Format,
        /// Add the stream to this manifest (it must describe the same file)
        #[arg(short, long)]
        manifest: Option<PathBuf>,
        /// Skip searching for encoder settings that reproduce the stream exactly
        #[arg(long)]
        no_match: bool,
    },
    /// Summary of a file: entropy map and the streams it contains
    Info {
        file: PathBuf,
        /// Number of blocks in the entropy map
        #[arg(long, default_value_t = 256)]
        blocks: usize,
        #[command(flatten)]
        filters: ScanArgs,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// Formats to look for, comma separated [default: gzip, zlib, zstd, xz, bzip2, lz4,
    /// deflate]. Brotli can't be scanned for; use `zscan try --format brotli`
    #[arg(long, value_delimiter = ',', default_values_t = Format::SCANNABLE.to_vec(), hide_default_value = true,
          value_parser = parse_scannable)]
    formats: Vec<Format>,
    /// Minimum decompressed size in bytes
    #[arg(long, default_value_t = DEFAULT_MIN_SIZE)]
    min_size: u64,
    /// Minimum compressed size for raw deflate/brotli (no checksum, so more false
    /// positives). Stored deflate blocks don't count; use 0 to find level-0 raw deflate
    #[arg(long, default_value_t = DEFAULT_RAW_MIN_COMPRESSED)]
    raw_min_compressed: u64,
    /// Reject raw deflate whose output entropy is above this, bits per byte (8 disables)
    #[arg(long, default_value_t = DEFAULT_RAW_MAX_ENTROPY)]
    raw_max_entropy: f64,
    /// Minimum decompressed/compressed ratio for raw deflate/brotli (0 with
    /// --raw-min-compressed 0 finds level-0 raw deflate)
    #[arg(long, default_value_t = DEFAULT_RAW_MIN_RATIO)]
    raw_min_ratio: f64,
    /// Minimum decompressed/compressed size ratio
    #[arg(long, default_value_t = 0.0)]
    min_ratio: f64,
    /// Reject streams whose decompressed entropy is above this (bits per byte, 0-8)
    #[arg(long)]
    max_entropy: Option<f64>,
    /// Largest decompressed size accepted for a single stream
    #[arg(long, default_value_t = DEFAULT_MAX_OUTPUT)]
    max_output: u64,
    /// Skip searching for the zlib settings that reproduce each stream exactly
    #[arg(long)]
    no_match: bool,
}

impl ScanArgs {
    fn options(&self) -> ScanOptions {
        ScanOptions {
            formats: self.formats.clone(),
            min_size: self.min_size,
            raw_min_compressed: self.raw_min_compressed,
            raw_max_entropy: (self.raw_max_entropy < 8.0).then_some(self.raw_max_entropy),
            raw_min_ratio: self.raw_min_ratio,
            min_ratio: self.min_ratio,
            max_entropy: self.max_entropy,
            max_output: self.max_output,
            match_params: !self.no_match,
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    if let Some(n) = cli.threads {
        rayon::ThreadPoolBuilder::new().num_threads(n.max(1)).build_global()?;
    }
    match cli.command {
        Command::Scan { file, output, stats, filters } => cmd_scan(&file, output.as_deref(), stats, &filters, cli.json),
        Command::Extract { file, manifest, dir, force, filters } => {
            cmd_extract(&file, manifest.as_deref(), &dir, force, &filters, cli.json)
        }
        Command::Pack { file, manifest, dir, output, dry_run, manifest_out, use_slack, relocate, align, force } => {
            let output = output.unwrap_or_else(|| default_packed_path(&file));
            let opts = PackOptions { verify_source: !force, use_zero_slack: use_slack, relocate, align };
            cmd_pack(&file, &manifest, &dir, &output, manifest_out.as_deref(), dry_run, &opts, cli.json)
        }
        Command::Unpack { file, dir, manifest, filters } => cmd_unpack(&file, &dir, manifest.as_deref(), &filters, cli.json),
        Command::Rebuild { dir, output } => cmd_rebuild(&dir, &output, cli.json),
        Command::Fields { file, manifest, window, min_value, apply } => {
            cmd_fields(&file, &manifest, &DetectOptions { window, min_global_value: min_value }, apply, cli.json)
        }
        Command::Try { file, at, format, manifest, no_match } => {
            cmd_try(&file, at, format, manifest.as_deref(), !no_match, cli.json)
        }
        Command::Info { file, blocks, filters } => cmd_info(&file, blocks, &filters, cli.json),
    }
}

fn build_manifest(file: &Path, data: &[u8], opts: ScanOptions) -> Manifest {
    let found = scan(data, &opts);
    Manifest::new(SourceInfo::describe(file, data), opts, found)
}

fn cmd_scan(file: &Path, output: Option<&Path>, stats: bool, filters: &ScanArgs, json: bool) -> Result<()> {
    let data = input::open(file)?;
    let opts = filters.options();
    let (found, scan_stats) = scan_with_stats(&data, &opts);
    let manifest = Manifest::new(SourceInfo::describe(file, &data), opts, found);
    if stats {
        print_stats(&scan_stats);
    }
    if let Some(out) = output {
        if same_file(out, file) {
            bail!("refusing to write the manifest over the input file");
        }
        manifest.save(out)?;
    }
    if json {
        println!("{}", manifest.to_json());
    } else {
        print_streams(&manifest.streams);
        println!("{} stream(s) found", manifest.streams.len());
        if let Some(out) = output {
            println!("manifest written to {}", out.display());
        }
    }
    Ok(())
}

fn cmd_extract(
    file: &Path,
    manifest: Option<&Path>,
    dir: &Path,
    force: bool,
    filters: &ScanArgs,
    json: bool,
) -> Result<()> {
    let data = input::open(file)?;
    let manifest = match manifest {
        Some(path) => Manifest::load(path)?,
        // Params only matter for packing, which needs a saved manifest anyway.
        None => build_manifest(file, &data, ScanOptions { match_params: false, ..filters.options() }),
    };
    let files = extract_all(&data, &manifest, dir, &ExtractOptions { verify_source: !force })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&files)?);
    } else {
        for f in &files {
            println!("{:>5}  {:#010x}  {:>12}  {}", f.id, f.offset, f.size, f.path.display());
        }
        println!("{} stream(s) extracted to {}", files.len(), dir.display());
    }
    Ok(())
}

#[derive(Serialize)]
struct InfoReport {
    file: String,
    size: u64,
    entropy: f64,
    block_size: u64,
    entropy_map: Vec<f64>,
    stream_count: usize,
    streams_by_format: Vec<(Format, usize)>,
    compressed_bytes: u64,
    decompressed_bytes: u64,
}

fn cmd_info(file: &Path, blocks: usize, filters: &ScanArgs, json: bool) -> Result<()> {
    let data = input::open(file)?;
    // Entropy of an n-byte block can't exceed log2(n), so tiny blocks all look alike.
    const MIN_BLOCK: usize = 256;
    let map = entropy_map(&data, blocks.min(data.len().div_ceil(MIN_BLOCK)));
    let found = scan(&data, &ScanOptions { match_params: false, ..filters.options() });
    let report = InfoReport {
        file: file.display().to_string(),
        size: data.len() as u64,
        entropy: shannon(&data),
        block_size: map.first().map_or(0, |b| b.len),
        entropy_map: map.iter().map(|b| (b.entropy * 1000.0).round() / 1000.0).collect(),
        stream_count: found.len(),
        streams_by_format: Format::ALL
            .iter()
            .map(|&f| (f, found.iter().filter(|s| s.format == f).count()))
            .filter(|&(_, n)| n > 0)
            .collect(),
        compressed_bytes: found.iter().map(|s| s.compressed_size).sum(),
        decompressed_bytes: found.iter().map(|s| s.decompressed_size).sum(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("file      {}", report.file);
    println!("size      {} bytes", report.size);
    println!("entropy   {:.3} bits/byte", report.entropy);
    let by_format: Vec<String> = report.streams_by_format.iter().map(|(f, n)| format!("{f} {n}")).collect();
    print!("streams   {}", report.stream_count);
    if !by_format.is_empty() {
        print!(" ({})", by_format.join(", "));
    }
    println!();
    if report.stream_count > 0 {
        let coverage = 100.0 * report.compressed_bytes as f64 / report.size.max(1) as f64;
        println!(
            "          {} bytes compressed -> {} decompressed, {coverage:.1}% of the file",
            report.compressed_bytes, report.decompressed_bytes
        );
    }
    if !map.is_empty() {
        const RAMP: &[u8] = b" .:-=+*#%@";
        const ROW: usize = 64;
        println!();
        println!("entropy map: {} blocks of {} bytes (' ' = 0 ... '@' = 8 bits/byte)", map.len(), report.block_size);
        for row in map.chunks(ROW) {
            let line: String = row
                .iter()
                .map(|b| char::from(RAMP[((b.entropy / 8.0 * RAMP.len() as f64) as usize).min(RAMP.len() - 1)]))
                .collect();
            println!("{:#010x}  |{line:<ROW$}|", row[0].offset);
        }
    }
    Ok(())
}

fn print_streams(streams: &[StreamEntry]) {
    if streams.is_empty() {
        return;
    }
    println!(
        "{:>5}  {:>10}  {:<7}  {:>12}  {:>12}  {:>7}  {:<22}  file",
        "id", "offset", "format", "compressed", "decompressed", "ratio", "exact params"
    );
    for s in streams {
        let params = s.exact_params.as_ref().map_or("-".into(), |p| p.to_string());
        println!(
            "{:>5}  {:#010x}  {:<7}  {:>12}  {:>12}  {:>7.2}  {:<22}  {}",
            s.id,
            s.offset,
            s.format.name(),
            s.compressed_size,
            s.decompressed_size,
            s.ratio(),
            params,
            s.file
        );
    }
}

#[derive(Serialize)]
struct PackReport<'a> {
    dry_run: bool,
    written: Option<String>,
    output_size: u64,
    streams: &'a [StreamPlan],
    field_updates: &'a [FieldUpdate],
}

#[allow(clippy::too_many_arguments)]
fn cmd_pack(
    file: &Path,
    manifest_path: &Path,
    dir: &Path,
    output: &Path,
    manifest_out: Option<&Path>,
    dry_run: bool,
    opts: &PackOptions,
    json: bool,
) -> Result<()> {
    if same_file(output, file) {
        bail!("refusing to overwrite the input file; choose a different --output");
    }
    let data = input::open(file)?;
    let manifest = Manifest::load(manifest_path)?;
    let edits = load_edits(dir, &manifest)?;
    let result = pack(&data, &manifest, &edits, opts)?;

    let mut written = None;
    if !dry_run && result.fits() {
        let mut packed_manifest = write_verified(output, &data, &result)?;
        written = Some(output.display().to_string());
        if let Some(path) = manifest_out {
            packed_manifest.source.path = output.display().to_string();
            packed_manifest.save(path)?;
        }
    }

    if json {
        let report = PackReport {
            dry_run,
            written: written.clone(),
            output_size: result.output_len(),
            streams: &result.streams,
            field_updates: &result.field_updates,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_pack_plan(&result.streams);
        for u in &result.field_updates {
            println!("  field at {:#010x} (stream {} {:?}): {} -> {}", u.offset, u.stream_id, u.measures, u.old, u.new);
        }
        let repacked = result.repacked().count();
        let unchanged = result.streams.len() - repacked - result.failures().count();
        println!("{repacked} stream(s) repacked, {unchanged} unchanged, {} field(s) updated", result.field_updates.len());
        if result.fits() && result.output_len() != data.len() as u64 {
            println!("the file grows from {} to {} bytes", data.len(), result.output_len());
        }
        if edits.is_empty() {
            println!("no edited files found in {}", dir.display());
        }
        match (&written, dry_run) {
            (Some(path), _) => println!("written to {path} (every stream verified)"),
            (None, true) if result.fits() => println!("dry run: every new stream fits and decodes correctly; nothing written"),
            _ => {}
        }
    }

    let failures: Vec<String> = result
        .failures()
        .map(|s| {
            let Outcome::TooLarge { best_size, available, relocatable } = s.outcome else { unreachable!() };
            let hint = if relocatable {
                "; its fields allow --relocate, which would move it to the end of the file"
            } else {
                "; --relocate needs offset and compressed-size fields for it (zscan fields) and no local header"
            };
            format!(
                "stream {} at {:#x}: {} bytes over (smallest encoding is {best_size} bytes, slot is {available}){hint}",
                s.id,
                s.offset,
                best_size - available
            )
        })
        .collect();
    if !failures.is_empty() {
        bail!("{} stream(s) don't fit, nothing written:\n  {}", failures.len(), failures.join("\n  "));
    }
    Ok(())
}

fn print_pack_plan(streams: &[StreamPlan]) {
    println!(
        "{:>5}  {:>10}  {:<7}  {:<10}  {:>10}  {:>10}  {:>8}  params",
        "id", "offset", "format", "status", "old size", "new size", "delta"
    );
    for s in streams {
        let (status, detail) = match &s.outcome {
            Outcome::Unchanged => ("unchanged", String::new()),
            Outcome::Repacked { params, reused_original_params, slack_used, relocated_to, .. } => {
                let mut detail = params.to_string();
                if *reused_original_params {
                    detail += " (original)";
                }
                if *slack_used > 0 {
                    detail += &format!(", {slack_used} bytes of slack");
                }
                if let Some(to) = relocated_to {
                    detail += &format!(", moved to {to:#x}");
                }
                (if relocated_to.is_some() { "relocated" } else { "repacked" }, detail)
            }
            Outcome::TooLarge { best_size, available, .. } => ("TOO LARGE", format!("{} bytes over", best_size - available)),
        };
        let delta = if s.outcome == Outcome::Unchanged { String::new() } else { format!("{:+}", s.delta()) };
        println!(
            "{:>5}  {:#010x}  {:<7}  {:<10}  {:>10}  {:>10}  {:>8}  {detail}",
            s.id,
            s.offset,
            s.format.name(),
            status,
            s.original_size,
            s.new_size(),
            delta
        );
    }
}

/// `dir/name.ext` -> `dir/name.packed.ext`
fn default_packed_path(input: &Path) -> PathBuf {
    let stem = input.file_stem().map_or("output".into(), |s| s.to_string_lossy());
    let name = match input.extension() {
        Some(ext) => format!("{stem}.packed.{}", ext.to_string_lossy()),
        None => format!("{stem}.packed"),
    };
    input.with_file_name(name)
}

/// Stream the packed file to a temporary file next to `path`, read it back and verify
/// every stream, then rename it into place. A failed write or verify never leaves a
/// half-written or wrong output behind. Returns the manifest for the output.
fn write_verified(path: &Path, input_data: &[u8], result: &PackResult) -> Result<Manifest> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".zscan-tmp");
    let tmp = PathBuf::from(tmp);
    let outcome = (|| -> Result<Manifest> {
        let file = std::fs::File::create(&tmp).map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
        result
            .write_to(input_data, std::io::BufWriter::with_capacity(8 << 20, file))
            .map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
        // The mapping must be dropped before the rename (Windows won't rename a mapped file).
        let written = input::open(&tmp)?;
        Ok(result.verify_output(&written)?)
    })();
    let manifest = match outcome {
        Ok(manifest) => manifest,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        bail!("{}: {e}", path.display());
    }
    Ok(manifest)
}

fn cmd_unpack(file: &Path, dir: &Path, manifest: Option<&Path>, filters: &ScanArgs, json: bool) -> Result<()> {
    let data = input::open(file)?;
    let manifest = match manifest {
        Some(path) => Manifest::load(path)?,
        None => build_manifest(file, &data, filters.options()),
    };
    let summary = unpack(&data, &manifest, dir)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "unpacked {} stream(s) to {}: {} by encoder settings, {} by preflate, {} stored as is",
            summary.streams,
            dir.display(),
            summary.encoded,
            summary.preflated,
            summary.stored
        );
        println!(
            "{} bytes outside streams, {} bytes of contents, {} bytes of reconstruction data",
            summary.gap_bytes, summary.content_bytes, summary.recon_bytes
        );
    }
    Ok(())
}

fn cmd_rebuild(dir: &Path, output: &Path, json: bool) -> Result<()> {
    let mut tmp = output.as_os_str().to_owned();
    tmp.push(".zscan-tmp");
    let tmp = PathBuf::from(tmp);
    let outcome = (|| -> Result<RebuildSummary> {
        let file = std::fs::File::create(&tmp).map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
        Ok(rebuild(dir, std::io::BufWriter::with_capacity(8 << 20, file))?)
    })();
    let summary = match outcome {
        Ok(summary) => summary,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if let Err(e) = std::fs::rename(&tmp, output) {
        let _ = std::fs::remove_file(&tmp);
        bail!("{}: {e}", output.display());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "rebuilt {} ({} bytes, {} streams); size and CRC-32 match the original",
            output.display(),
            summary.bytes,
            summary.streams
        );
    }
    Ok(())
}

#[derive(Serialize)]
struct FieldsReport<'a> {
    candidates: &'a [FieldCandidate],
    added: &'a [FieldCandidate],
}

fn cmd_fields(file: &Path, manifest_path: &Path, opts: &DetectOptions, apply: bool, json: bool) -> Result<()> {
    let data = input::open(file)?;
    let mut manifest = Manifest::load(manifest_path)?;
    manifest.source.check(&data)?;
    let candidates = detect_fields(&data, &manifest, opts);
    let added = if apply { apply_unambiguous(&mut manifest, &candidates) } else { Vec::new() };
    if apply {
        check_fields(&data, &manifest)?;
        manifest.save(manifest_path)?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&FieldsReport { candidates: &candidates, added: &added })?);
        return Ok(());
    }
    println!("{:>6}  {:<17}  {:>10}  {:>5}  {:<6}  where", "stream", "holds", "at", "width", "order");
    for c in &candidates {
        let f = &c.field;
        let status = if added.contains(c) { "added" } else if apply { "ambiguous, not added" } else { "" };
        println!(
            "{:>6}  {:<17}  {:#010x}  {:>5}  {:<6}  {:<5}  {status}",
            c.stream_id,
            format!("{:?}", f.measures).to_lowercase(),
            f.offset,
            f.width,
            format!("{:?}", f.endian).to_lowercase(),
            if c.near { "near" } else { "table" }
        );
    }
    println!("{} candidate(s)", candidates.len());
    if apply {
        println!("{} field(s) added to {}", added.len(), manifest_path.display());
    } else if !candidates.is_empty() {
        println!("run with --apply to add the unambiguous ones to the manifest");
    }
    Ok(())
}

fn parse_offset(s: &str) -> Result<u64, String> {
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse(),
    };
    parsed.map_err(|e| format!("invalid offset '{s}': {e}"))
}

fn parse_scannable(s: &str) -> Result<Format, String> {
    let format: Format = s.parse()?;
    if !format.scannable() {
        return Err(format!(
            "{format} can't be scanned for: it has no magic number and random bytes decode as it too \
             readily. Use `zscan try <file> --at <offset> --format {format}` instead"
        ));
    }
    Ok(format)
}

fn cmd_try(file: &Path, at: u64, format: Format, manifest_path: Option<&Path>, match_params: bool, json: bool) -> Result<()> {
    let data = input::open(file)?;
    let found = decode_at(&data, at, format, DEFAULT_MAX_OUTPUT, match_params)
        .map_err(|e| anyhow::anyhow!("no {format} stream decodes at {at:#x}: {e}"))?;
    let mut added = None;
    if let Some(path) = manifest_path {
        let mut manifest = Manifest::load(path)?;
        manifest.source.check(&data)?;
        added = Some(manifest.add_stream(found.clone())?);
        manifest.save(path)?;
    }
    if json {
        let report = serde_json::json!({
            "offset": found.offset,
            "format": found.format,
            "compressed_size": found.compressed_size,
            "decompressed_size": found.decompressed_size,
            "crc32": format!("{:08x}", found.crc32),
            "exact_params": found.exact_params,
            "added_as": added,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{format} stream at {:#x}: {} bytes -> {} bytes, exact params {}",
            found.offset,
            found.compressed_size,
            found.decompressed_size,
            found.exact_params.as_ref().map_or("-".into(), |p| p.to_string())
        );
        if let (Some(id), Some(path)) = (added, manifest_path) {
            println!("added to {} as stream {id}", path.display());
        }
    }
    Ok(())
}

fn print_stats(stats: &ScanStats) {
    let mib = stats.bytes as f64 / (1 << 20) as f64;
    let phase = |name: &str, d: std::time::Duration| {
        eprintln!("  {name:<16} {:>9.2} s  {:>9.1} MiB/s", d.as_secs_f64(), mib / d.as_secs_f64().max(1e-9));
    };
    eprintln!("scan of {mib:.1} MiB:");
    phase("verified pass", stats.verified_pass);
    phase("unverified pass", stats.raw_pass);
    phase("param matching", stats.param_matching);
    phase("total", stats.total());
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
