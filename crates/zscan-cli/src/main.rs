use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use zscan_core::entropy::{entropy_map, shannon};
use zscan_core::scan::{DEFAULT_MAX_OUTPUT, DEFAULT_MIN_SIZE, DEFAULT_RAW_MAX_ENTROPY, DEFAULT_RAW_MIN_COMPRESSED};
use zscan_core::{ExtractOptions, Format, Manifest, ScanOptions, SourceInfo, StreamEntry, extract_all, input, scan};

#[derive(Parser)]
#[command(name = "zscan", version, about = "Find, extract and reinject compressed streams inside binary files")]
struct Cli {
    /// Print machine-readable JSON on stdout instead of text
    #[arg(long, global = true)]
    json: bool,

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
    /// Minimum decompressed/compressed size ratio
    #[arg(long, default_value_t = 0.0)]
    min_ratio: f64,
    /// Reject streams whose decompressed entropy is above this (bits per byte, 0-8)
    #[arg(long)]
    max_entropy: Option<f64>,
    /// Largest decompressed size accepted for a single stream
    #[arg(long, default_value_t = DEFAULT_MAX_OUTPUT)]
    max_output: u64,
}

impl ScanArgs {
    fn options(&self) -> ScanOptions {
        ScanOptions {
            formats: self.formats.clone(),
            min_size: self.min_size,
            raw_min_compressed: self.raw_min_compressed,
            raw_max_entropy: (self.raw_max_entropy < 8.0).then_some(self.raw_max_entropy),
            min_ratio: self.min_ratio,
            max_entropy: self.max_entropy,
            max_output: self.max_output,
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
    match cli.command {
        Command::Scan { file, output, filters } => cmd_scan(&file, output.as_deref(), &filters, cli.json),
        Command::Extract { file, manifest, dir, force, filters } => {
            cmd_extract(&file, manifest.as_deref(), &dir, force, &filters, cli.json)
        }
        Command::Info { file, blocks, filters } => cmd_info(&file, blocks, &filters, cli.json),
    }
}

fn build_manifest(file: &Path, data: &[u8], opts: ScanOptions) -> Manifest {
    let found = scan(data, &opts);
    Manifest::new(SourceInfo::describe(file, data), opts, found)
}

fn cmd_scan(file: &Path, output: Option<&Path>, filters: &ScanArgs, json: bool) -> Result<()> {
    let data = input::open(file)?;
    let manifest = build_manifest(file, &data, filters.options());
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
        None => build_manifest(file, &data, filters.options()),
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
    let found = scan(&data, &filters.options());
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
        "{:>5}  {:>10}  {:<7}  {:>12}  {:>12}  {:>7}  file",
        "id", "offset", "format", "compressed", "decompressed", "ratio"
    );
    for s in streams {
        println!(
            "{:>5}  {:#010x}  {:<7}  {:>12}  {:>12}  {:>7.2}  {}",
            s.id,
            s.offset,
            s.format.name(),
            s.compressed_size,
            s.decompressed_size,
            s.ratio(),
            s.file
        );
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
