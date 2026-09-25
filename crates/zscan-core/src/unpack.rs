//! Unpack and rebuild: expand a file into its streams' decompressed contents plus
//! everything needed to recreate it bit for bit without the original (as precomp does),
//! so that it can be stored or compressed better and restored exactly.
//!
//! An unpack directory holds:
//! - `unpack.json`: the index (source size and CRC, and how to recreate each stream)
//! - `gaps.bin`: every byte outside the streams, in order
//! - `streams/`: decompressed contents, named as extract names them
//! - `recon/`: per-stream reconstruction data, where needed
//!
//! Each stream is recreated by the first method that reproduces it exactly, checked at
//! unpack time so rebuild can't silently differ:
//! 1. encode: the scan's exact encoder settings plus the original header bytes;
//! 2. preflate: deflate-family streams zlib can't reproduce, rebuilt by `preflate-rs`
//!    from the contents and a small correction record;
//! 3. stored: the compressed bytes verbatim (no size gain, but always exact).

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;

use preflate_rs::{PreflateConfig, preflate_whole_deflate_stream, recreate_whole_deflate_stream};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::checksum::crc32;
use crate::codec::{DecodeCtx, Decoded, Format, codec_for};
use crate::error::{Error, Result, io_err};
use crate::extract::decode_stream;
use crate::input;
use crate::manifest::{Manifest, SourceInfo, StreamEntry, hex_u32, is_safe_filename};
use crate::output::write_via_temp;
use crate::params::EncoderParams;

pub const UNPACK_VERSION: u32 = 1;
const INDEX: &str = "unpack.json";
const GAPS: &str = "gaps.bin";
const STREAMS: &str = "streams";
const RECON: &str = "recon";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnpackIndex {
    pub version: u32,
    pub source: SourceInfo,
    /// In offset order.
    pub streams: Vec<UnpackedStream>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnpackedStream {
    pub id: u32,
    pub offset: u64,
    pub format: Format,
    pub compressed_size: u64,
    pub decompressed_size: u64,
    #[serde(with = "hex_u32")]
    pub crc32: u32,
    /// Contents file in `streams/`.
    pub file: String,
    pub method: Method,
}

impl UnpackedStream {
    pub fn end(&self) -> u64 {
        self.offset + self.compressed_size
    }
}

/// How a stream is recreated from its contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Method {
    /// Encode the contents with these settings, reusing the original header bytes
    /// (everything before the compressed body: a gzip header, say).
    Encode {
        #[serde(with = "hex_bytes")]
        header: Vec<u8>,
        params: EncoderParams,
    },
    /// Header, then the deflate body rebuilt by preflate from the contents and the
    /// corrections in `recon/<recon>`, then the trailer, all from the original.
    Preflate {
        #[serde(with = "hex_bytes")]
        header: Vec<u8>,
        #[serde(with = "hex_bytes")]
        trailer: Vec<u8>,
        recon: String,
    },
    /// The compressed stream verbatim, in `recon/<recon>`.
    Stored { recon: String },
}

impl Method {
    fn recon_file(&self) -> Option<&str> {
        match self {
            Method::Encode { .. } => None,
            Method::Preflate { recon, .. } | Method::Stored { recon } => Some(recon),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UnpackSummary {
    pub streams: usize,
    pub encoded: usize,
    pub preflated: usize,
    pub stored: usize,
    /// Bytes in `gaps.bin`.
    pub gap_bytes: u64,
    /// Bytes in `streams/`.
    pub content_bytes: u64,
    /// Bytes in `recon/`.
    pub recon_bytes: u64,
}

/// Unpack `data` (described by `manifest`) into `dir`, which must not exist or be empty.
pub fn unpack(data: &[u8], manifest: &Manifest, dir: &Path) -> Result<UnpackSummary> {
    manifest.source.check(data)?;
    let mut streams: Vec<&StreamEntry> = manifest.streams.iter().collect();
    streams.sort_by_key(|s| s.offset);
    check_layout(streams.iter().map(|s| (s.id, s.offset, s.end(), s.file.as_str())), data.len() as u64)?;
    if fs::read_dir(dir).is_ok_and(|mut d| d.next().is_some()) {
        return Err(Error::Pack(format!("{} is not empty; unpack needs a new or empty directory", dir.display())));
    }
    for sub in [STREAMS, RECON] {
        let path = dir.join(sub);
        fs::create_dir_all(&path).map_err(io_err(&path))?;
    }

    let gaps_path = dir.join(GAPS);
    let mut gaps = BufWriter::new(File::create(&gaps_path).map_err(io_err(&gaps_path))?);
    let mut pos = 0;
    let mut gap_bytes = 0;
    for s in &streams {
        gaps.write_all(&data[pos as usize..s.offset as usize]).map_err(io_err(&gaps_path))?;
        gap_bytes += s.offset - pos;
        pos = s.end();
    }
    gaps.write_all(&data[pos as usize..]).map_err(io_err(&gaps_path))?;
    gap_bytes += data.len() as u64 - pos;
    gaps.flush().map_err(io_err(&gaps_path))?;

    let largest = streams.iter().map(|s| s.decompressed_size).max().unwrap_or(0);
    let max_output = usize::try_from(largest).unwrap_or(usize::MAX);
    let unpacked: Vec<(UnpackedStream, u64)> = streams
        .par_iter()
        .map_init(|| DecodeCtx::new(max_output), |ctx, entry| unpack_stream(data, entry, dir, ctx))
        .collect::<Result<_>>()?;

    let mut summary = UnpackSummary { streams: unpacked.len(), gap_bytes, ..Default::default() };
    for (s, recon_len) in &unpacked {
        summary.content_bytes += s.decompressed_size;
        summary.recon_bytes += recon_len;
        match s.method {
            Method::Encode { .. } => summary.encoded += 1,
            Method::Preflate { .. } => summary.preflated += 1,
            Method::Stored { .. } => summary.stored += 1,
        }
    }
    let index = UnpackIndex {
        version: UNPACK_VERSION,
        source: manifest.source.clone(),
        streams: unpacked.into_iter().map(|(s, _)| s).collect(),
    };
    let index_path = dir.join(INDEX);
    let json = serde_json::to_string_pretty(&index).expect("index serialization cannot fail");
    fs::write(&index_path, json + "\n").map_err(io_err(&index_path))?;
    Ok(summary)
}

fn unpack_stream(data: &[u8], entry: &StreamEntry, dir: &Path, ctx: &mut DecodeCtx) -> Result<(UnpackedStream, u64)> {
    let decoded = decode_stream(data, entry, ctx)?;
    let stream = &data[entry.offset as usize..entry.end() as usize];
    let contents_path = dir.join(STREAMS).join(&entry.file);
    fs::write(&contents_path, &decoded.data).map_err(io_err(&contents_path))?;

    let recon_name = format!("{}.bin", entry.id);
    let (method, recon) = choose_method(entry, stream, &decoded, &recon_name);
    if let Some(bytes) = &recon {
        let path = dir.join(RECON).join(&recon_name);
        fs::write(&path, bytes).map_err(io_err(&path))?;
    }
    let unpacked = UnpackedStream {
        id: entry.id,
        offset: entry.offset,
        format: entry.format,
        compressed_size: entry.compressed_size,
        decompressed_size: entry.decompressed_size,
        crc32: entry.crc32,
        file: entry.file.clone(),
        method,
    };
    Ok((unpacked, recon.map_or(0, |r| r.len() as u64)))
}

/// The first method that recreates `stream` exactly, and its reconstruction data.
fn choose_method(entry: &StreamEntry, stream: &[u8], decoded: &Decoded, recon_name: &str) -> (Method, Option<Vec<u8>>) {
    let header = stream[..decoded.body.start].to_vec();
    if let Some(params) = &entry.exact_params {
        let method = Method::Encode { header: header.clone(), params: params.clone() };
        if recreate(entry.format, &method, &decoded.data, None).is_ok_and(|s| s == stream) {
            return (method, None);
        }
    }
    if entry.format.is_deflate_family() {
        let body = &stream[decoded.body.clone()];
        let config = PreflateConfig {
            max_chain_length: 4096,
            plain_text_limit: decoded.data.len() + 1,
            verify_compression: false, // checked below, end to end
        };
        if let Ok((result, plain)) = preflate_whole_deflate_stream(body, &config) {
            let method = Method::Preflate {
                header,
                trailer: stream[decoded.body.end..].to_vec(),
                recon: recon_name.to_string(),
            };
            let same = result.compressed_size == body.len()
                && plain.text() == decoded.data.as_slice()
                && recreate(entry.format, &method, &decoded.data, Some(&result.corrections)).is_ok_and(|s| s == stream);
            if same {
                return (method, Some(result.corrections));
            }
        }
    }
    (Method::Stored { recon: recon_name.to_string() }, Some(stream.to_vec()))
}

/// Recreate a stream from its contents (`data`) and reconstruction data.
fn recreate(format: Format, method: &Method, data: &[u8], recon: Option<&[u8]>) -> std::result::Result<Vec<u8>, String> {
    match method {
        Method::Encode { header, params } => {
            // Encoders only look at the original stream for its header.
            let codec = codec_for(format);
            let decoded = Decoded { compressed_size: header.len(), body: header.len()..header.len(), data: Vec::new(), original_name: None };
            let params = codec.adapt_params(header, &decoded, params)?;
            Ok(codec.encode(header, &decoded, data, &params))
        }
        Method::Preflate { header, trailer, .. } => {
            let corrections = recon.ok_or("missing preflate corrections")?;
            let body = recreate_whole_deflate_stream(data, corrections).map_err(|e| format!("preflate: {e:?}"))?;
            Ok([header.as_slice(), &body, trailer].concat())
        }
        Method::Stored { .. } => Ok(recon.ok_or("missing stored stream")?.to_vec()),
    }
}

/// Streams must be in order, non-overlapping, inside the file, with safe file names.
fn check_layout<'a>(streams: impl Iterator<Item = (u32, u64, u64, &'a str)>, size: u64) -> Result<()> {
    let mut prev_end = 0;
    for (id, offset, end, file) in streams {
        if offset < prev_end || end > size {
            return Err(Error::InvalidManifest(format!("stream {id} overlaps another or runs past the end")));
        }
        if !is_safe_filename(file) {
            return Err(Error::BadFilename(file.to_string()));
        }
        prev_end = end;
    }
    Ok(())
}

pub fn load_index(dir: &Path) -> Result<UnpackIndex> {
    let path = dir.join(INDEX);
    let index: UnpackIndex = serde_json::from_str(&fs::read_to_string(&path).map_err(io_err(&path))?)?;
    if index.version != UNPACK_VERSION {
        return Err(Error::ManifestVersion { found: index.version, expected: UNPACK_VERSION });
    }
    Ok(index)
}

#[derive(Debug, Clone, Serialize)]
pub struct RebuildSummary {
    pub bytes: u64,
    pub streams: usize,
}

/// Recreate the original file from an unpack directory, writing it to `out`. Fails if
/// any contents file was changed, or if the result's size or CRC-32 differs from the
/// original's (in which case `out` has received bad data; write to a temporary file).
/// [`rebuild`] into the file `path`, which appears only once its size and CRC-32 have
/// been checked.
pub fn rebuild_file(dir: &Path, path: &Path) -> Result<RebuildSummary> {
    write_via_temp(path, |tmp| {
        let file = File::create(tmp).map_err(io_err(tmp))?;
        rebuild(dir, BufWriter::with_capacity(8 << 20, file))
    })
}

pub fn rebuild(dir: &Path, out: impl Write) -> Result<RebuildSummary> {
    let index = load_index(dir)?;
    check_layout(index.streams.iter().map(|s| (s.id, s.offset, s.end(), s.file.as_str())), index.source.size)?;
    if let Some(bad) = index.streams.iter().filter_map(|s| s.method.recon_file()).find(|f| !is_safe_filename(f)) {
        return Err(Error::BadFilename(bad.to_string()));
    }
    let gaps = input::open(&dir.join(GAPS))?;
    let stream_bytes: u64 = index.streams.iter().map(|s| s.compressed_size).sum();
    if gaps.len() as u64 + stream_bytes != index.source.size {
        return Err(Error::SourceMismatch(format!(
            "{GAPS} is {} bytes, the index needs {}",
            gaps.len(),
            index.source.size - stream_bytes
        )));
    }

    let mut out = HashingWriter { inner: out, hasher: crc32fast::Hasher::new(), written: 0 };
    let write_err = |e: io::Error| Error::Io { path: "rebuild output".into(), source: e };
    let (mut gap_pos, mut file_pos) = (0usize, 0u64);
    // Rebuild in batches big enough that one slow stream (xz, zstd -19) doesn't leave
    // the other threads idle, but bounded so memory doesn't grow with the file.
    const BATCH_BYTES: u64 = 256 << 20;
    let mut batches = Vec::new();
    let (mut start, mut bytes) = (0, 0);
    for (i, s) in index.streams.iter().enumerate() {
        bytes += s.compressed_size.max(s.decompressed_size);
        if bytes >= BATCH_BYTES {
            batches.push(&index.streams[start..=i]);
            (start, bytes) = (i + 1, 0);
        }
    }
    batches.push(&index.streams[start..]);
    for chunk in batches {
        let rebuilt: Vec<Vec<u8>> = chunk.par_iter().map(|s| rebuild_stream(dir, s)).collect::<Result<_>>()?;
        for (s, bytes) in chunk.iter().zip(rebuilt) {
            let gap = (s.offset - file_pos) as usize;
            out.write_all(&gaps[gap_pos..gap_pos + gap]).map_err(write_err)?;
            out.write_all(&bytes).map_err(write_err)?;
            gap_pos += gap;
            file_pos = s.end();
        }
    }
    out.write_all(&gaps[gap_pos..]).map_err(write_err)?;
    out.flush().map_err(write_err)?;

    let crc = out.hasher.finalize();
    if out.written != index.source.size || crc != index.source.crc32 {
        return Err(Error::Verify {
            id: 0,
            offset: 0,
            reason: format!(
                "rebuilt file is {} bytes with CRC-32 {crc:08x}; the original was {} bytes, {:08x}",
                out.written, index.source.size, index.source.crc32
            ),
        });
    }
    Ok(RebuildSummary { bytes: out.written, streams: index.streams.len() })
}

fn rebuild_stream(dir: &Path, s: &UnpackedStream) -> Result<Vec<u8>> {
    let fail = |reason: String| Error::Stream { id: s.id, offset: s.offset, reason };
    let contents_path = dir.join(STREAMS).join(&s.file);
    let data = fs::read(&contents_path).map_err(io_err(&contents_path))?;
    if data.len() as u64 != s.decompressed_size || crc32(&data) != s.crc32 {
        return Err(fail(format!(
            "{} changed since unpack; rebuild only restores the original (use pack for edits)",
            s.file
        )));
    }
    let recon = match s.method.recon_file() {
        Some(name) => {
            let path = dir.join(RECON).join(name);
            Some(fs::read(&path).map_err(io_err(&path))?)
        }
        None => None,
    };
    let bytes = recreate(s.format, &s.method, &data, recon.as_deref()).map_err(fail)?;
    if bytes.len() as u64 != s.compressed_size {
        return Err(fail(format!("recreated {} bytes, expected {}", bytes.len(), s.compressed_size)));
    }
    Ok(bytes)
}

struct HashingWriter<W> {
    inner: W,
    hasher: crc32fast::Hasher,
    written: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() % 2 != 0 {
            return Err(D::Error::custom("odd-length hex string"));
        }
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(D::Error::custom))
            .collect()
    }
}
