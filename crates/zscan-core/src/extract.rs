//! Extracting the streams listed in a manifest.

use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::Serialize;

use crate::checksum::crc32;
use crate::codec::{DecodeCtx, Decoded, codec_for};
use crate::error::{Error, Result, io_err};
use crate::manifest::{Manifest, StreamEntry, is_safe_filename};

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Refuse to run if the input's size or CRC-32 differs from the manifest.
    pub verify_source: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self { verify_source: true }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedFile {
    pub id: u32,
    pub offset: u64,
    pub path: PathBuf,
    pub size: u64,
}

/// Decode one manifest stream from `data` and check it against the manifest's
/// sizes and checksum.
pub fn decode_stream(data: &[u8], entry: &StreamEntry, ctx: &mut DecodeCtx) -> Result<Decoded> {
    let fail = |reason: String| Error::Stream { id: entry.id, offset: entry.offset, reason };
    let start = usize::try_from(entry.offset)
        .ok()
        .filter(|&o| o <= data.len())
        .ok_or_else(|| fail("offset is past the end of the input".into()))?;
    let decoded = codec_for(entry.format)
        .decode(&data[start..], ctx)
        .map_err(|e| fail(format!("{} decode failed: {e}", entry.format)))?;
    if decoded.compressed_size as u64 != entry.compressed_size {
        return Err(fail(format!(
            "compressed size is {}, manifest says {}",
            decoded.compressed_size, entry.compressed_size
        )));
    }
    if decoded.data.len() as u64 != entry.decompressed_size {
        return Err(fail(format!(
            "decompressed size is {}, manifest says {}",
            decoded.data.len(),
            entry.decompressed_size
        )));
    }
    let actual = crc32(&decoded.data);
    if actual != entry.crc32 {
        return Err(fail(format!("CRC-32 is {actual:08x}, manifest says {:08x}", entry.crc32)));
    }
    Ok(decoded)
}

/// Write every stream in `manifest` to `out_dir`, verifying each one on the way.
/// Streams are decoded in parallel; the result is in manifest order.
pub fn extract_all(
    data: &[u8],
    manifest: &Manifest,
    out_dir: &Path,
    opts: &ExtractOptions,
) -> Result<Vec<ExtractedFile>> {
    if opts.verify_source {
        manifest.source.check(data)?;
    }
    // Validate everything before writing anything.
    if let Some(bad) = manifest.streams.iter().find(|s| !is_safe_filename(&s.file)) {
        return Err(Error::BadFilename(bad.file.clone()));
    }
    fs::create_dir_all(out_dir).map_err(io_err(out_dir))?;

    let largest = manifest.streams.iter().map(|s| s.decompressed_size).max().unwrap_or(0);
    let max_output = usize::try_from(largest).unwrap_or(usize::MAX);
    manifest
        .streams
        .par_iter()
        .map_init(
            || DecodeCtx::new(max_output),
            |ctx, entry| {
                let bytes = decode_stream(data, entry, ctx)?.data;
                let path = out_dir.join(&entry.file);
                fs::write(&path, &bytes).map_err(io_err(&path))?;
                Ok(ExtractedFile { id: entry.id, offset: entry.offset, path, size: bytes.len() as u64 })
            },
        )
        .collect()
}
