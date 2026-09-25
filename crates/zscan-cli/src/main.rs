use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use zscan_core::entropy::{entropy_map, shannon};
use zscan_core::scan::{DEFAULT_MAX_OUTPUT, DEFAULT_MIN_SIZE, DEFAULT_RAW_MAX_ENTROPY, DEFAULT_RAW_MIN_COMPRESSED, DEFAULT_RAW_MIN_RATIO};
use zscan_core::{
    ExtractOptions, Format, Manifest, Outcome, PackOptions, PackResult, ScanOptions, ScanStats, SourceInfo, StreamEntry,
    StreamPlan, extract_all, input, load_edits, pack, scan, scan_with_stats,
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
        /// the file finds the stream's end by decoding it, not from a stored size
        #[arg(long)]
        use_slack: bool,
        /// Pack even if the input's size or CRC no longer matches the manifest
        #[arg(long)]
        force: bool,
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
    /// Formats to look for, comma separated
    #[arg(long, value_delimiter = ',', default_values_t = Format::ALL.to_vec())]
    formats: Vec<Format>,
    /// Minimum decompressed size in bytes
    #[arg(long, default_value_t = DEFAULT_MIN_SIZE)]
    min_size: u64,
    /// Minimum compressed size for raw deflate (no checksum, so more false positives)
    #[arg(long, default_value_t = DEFAULT_RAW_MIN_COMPRESSED)]
    raw_min_compressed: u64,
    /// Reject raw deflate whose output entropy is above this, bits per byte (8 disables)
    #[arg(long, default_value_t = DEFAULT_RAW_MAX_ENTROPY)]
    raw_max_entropy: f64,
    /// Minimum decompressed/compressed ratio for raw deflate (0 finds level-0 streams)
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
        Command::Pack { file, manifest, dir, output, dry_run, manifest_out, use_slack, force } => {
            let output = output.unwrap_or_else(|| default_packed_path(&file));
            let opts = PackOptions { verify_source: !force, use_zero_slack: use_slack };
            cmd_pack(&file, &manifest, &dir, &output, manifest_out.as_deref(), dry_run, &opts, cli.json)
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
        let params = s.params.deflate_params().filter(|_| s.params.exact_match).map_or("-".into(), |p| p.to_string());
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
    streams: &'a [StreamPlan],
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
        let report = PackReport { dry_run, written: written.clone(), streams: &result.streams };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_pack_plan(&result.streams);
        let repacked = result.repacked().count();
        let unchanged = result.streams.len() - repacked - result.failures().count();
        println!("{repacked} stream(s) repacked, {unchanged} unchanged");
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
            let Outcome::TooLarge { best_size, available } = s.outcome else { unreachable!() };
            format!(
                "stream {} at {:#x}: {} bytes over (smallest encoding is {best_size} bytes, slot is {available})",
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
            Outcome::Repacked { params, reused_original_params, slack_used, .. } => {
                let mut detail = params.to_string();
                if *reused_original_params {
                    detail += " (original)";
                }
                if *slack_used > 0 {
                    detail += &format!(", {slack_used} bytes of slack");
                }
                ("repacked", detail)
            }
            Outcome::TooLarge { best_size, available } => ("TOO LARGE", format!("{} bytes over", best_size - available)),
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

fn print_stats(stats: &ScanStats) {
    let mib = stats.bytes as f64 / (1 << 20) as f64;
    let phase = |name: &str, d: std::time::Duration| {
        eprintln!("  {name:<16} {:>9.2} s  {:>9.1} MiB/s", d.as_secs_f64(), mib / d.as_secs_f64().max(1e-9));
    };
    eprintln!("scan of {mib:.1} MiB:");
    phase("gzip/zlib pass", stats.verified_pass);
    phase("raw deflate pass", stats.raw_pass);
    phase("param matching", stats.param_matching);
    phase("total", stats.total());
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
