//! The [`Codec`] trait and the types shared by every stream format.

use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
use serde::{Deserialize, Serialize};

use crate::codecs::{DeflateCodec, GzipCodec, ZlibCodec};
use crate::deflater::DeflateParams;

/// Compressed stream formats. Declaration order is scan priority: when two formats
/// match at the same offset, the earlier (better verified) one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// RFC 1952: header, deflate body, CRC-32 + size trailer.
    Gzip,
    /// RFC 1950: 2-byte header, deflate body, Adler-32 trailer.
    Zlib,
    /// RFC 1951 raw deflate. No header or checksum, so the weakest evidence.
    Deflate,
}

impl Format {
    pub const ALL: [Format; 3] = [Format::Gzip, Format::Zlib, Format::Deflate];

    pub fn name(self) -> &'static str {
        match self {
            Format::Gzip => "gzip",
            Format::Zlib => "zlib",
            Format::Deflate => "deflate",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "gzip" | "gz" => Ok(Format::Gzip),
            "zlib" => Ok(Format::Zlib),
            "deflate" | "raw" => Ok(Format::Deflate),
            other => Err(format!("unknown format '{other}' (expected gzip, zlib or deflate)")),
        }
    }
}

/// zlib compression strategies (for parameter matching in build stage 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Default,
    Filtered,
    HuffmanOnly,
    Rle,
    Fixed,
}

/// Compressor settings known for a stream. At stage 1 only what the header states is
/// filled in; stage 2 fills in the rest by recompressing and sets `exact_match`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_bits: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_level: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,
    /// True when recompressing with these params reproduces the original bytes exactly.
    #[serde(default)]
    pub exact_match: bool,
}

impl CompressionParams {
    /// Params known to reproduce the original stream exactly.
    pub fn exact(p: DeflateParams) -> Self {
        Self {
            level: Some(p.level),
            window_bits: Some(p.window_bits),
            mem_level: Some(p.mem_level),
            strategy: Some(p.strategy),
            exact_match: true,
        }
    }

    /// The complete settings, if every field is known.
    pub fn deflate_params(&self) -> Option<DeflateParams> {
        Some(DeflateParams {
            level: self.level?,
            window_bits: self.window_bits?,
            mem_level: self.mem_level?,
            strategy: self.strategy?,
        })
    }
}

/// A successfully decoded stream.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Bytes the whole stream occupies in the input, including header and trailer.
    pub compressed_size: usize,
    /// Where the raw deflate body sits within the stream. Everything before it is header.
    pub body: Range<usize>,
    pub data: Vec<u8>,
    pub params: CompressionParams,
    /// File name stored in the stream header (gzip FNAME), if any.
    pub original_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid or unsupported header")]
    BadHeader,
    #[error("invalid deflate data")]
    InvalidData,
    #[error("stream is truncated")]
    Truncated,
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("decompressed size exceeds the {0}-byte limit")]
    TooLarge(usize),
}

/// One compressed stream format. Each format lives in its own file under `codecs/`.
pub trait Codec: Send + Sync {
    fn format(&self) -> Format;

    /// Whether the format carries its own integrity check (header check and/or checksum).
    /// The scanner trusts these formats first and only looks for raw deflate in the gaps.
    fn self_verifying(&self) -> bool;

    /// Cheap test on the first few bytes of `data`. May return false positives but
    /// must never reject a stream that `decode` would accept from a real encoder.
    fn probe(&self, data: &[u8]) -> bool;

    /// Decode a stream that starts at `data[0]`. `data` may extend past the stream end.
    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError>;

    /// Build a complete stream from `header` (the original stream's bytes before its
    /// body, reused as-is), a new raw deflate `body`, and the uncompressed `data` it
    /// encodes (for the trailer).
    fn wrap(&self, header: &[u8], body: &[u8], data: &[u8]) -> Vec<u8>;
}

/// The codec implementation for a format.
pub fn codec_for(format: Format) -> &'static dyn Codec {
    match format {
        Format::Gzip => &GzipCodec,
        Format::Zlib => &ZlibCodec,
        Format::Deflate => &DeflateCodec,
    }
}

const INITIAL_OUTPUT: usize = 64 * 1024;

/// Reusable decoder state. Scanning tries to decode at a huge number of offsets, so the
/// inflater and output buffer are allocated once here and reused. Use one per thread.
pub struct DecodeCtx {
    inflater: Box<DecompressorOxide>,
    buf: Vec<u8>,
    max_output: usize,
}

impl DecodeCtx {
    /// `max_output` caps the decompressed size of any single stream.
    pub fn new(max_output: usize) -> Self {
        Self { inflater: Box::default(), buf: Vec::new(), max_output: max_output.max(1) }
    }

    pub fn max_output(&self) -> usize {
        self.max_output
    }

    /// Inflate the raw deflate stream at the start of `input`.
    /// Returns (bytes consumed, bytes produced); the output is in `self.output(len)`.
    pub(crate) fn inflate(&mut self, input: &[u8]) -> Result<(usize, usize), DecodeError> {
        self.inflater.init();
        let floor = INITIAL_OUTPUT.min(self.max_output);
        if self.buf.len() < floor {
            let len = self.buf.capacity().clamp(floor, self.max_output);
            self.buf.resize(len, 0);
        }
        // The whole remaining input is available up front, so running out of input
        // means the stream is truncated.
        let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let (mut in_pos, mut out_pos) = (0, 0);
        loop {
            let (status, n_in, n_out) =
                decompress(&mut self.inflater, &input[in_pos..], &mut self.buf[..], out_pos, flags);
            in_pos += n_in;
            out_pos += n_out;
            match status {
                TINFLStatus::Done => return Ok((in_pos, out_pos)),
                TINFLStatus::HasMoreOutput => {
                    if self.buf.len() >= self.max_output {
                        return Err(DecodeError::TooLarge(self.max_output));
                    }
                    let len = self.buf.len().saturating_mul(2).min(self.max_output);
                    self.buf.resize(len, 0);
                }
                TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                    return Err(DecodeError::Truncated);
                }
                _ => return Err(DecodeError::InvalidData),
            }
        }
    }

    pub(crate) fn output(&self, len: usize) -> &[u8] {
        &self.buf[..len]
    }

    /// Move the first `len` output bytes out of the context.
    pub(crate) fn take_output(&mut self, len: usize) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.buf);
        out.truncate(len);
        out
    }

    /// Hand a buffer back (e.g. `Decoded::data` once finished with it) to avoid reallocating.
    pub fn recycle(&mut self, mut buf: Vec<u8>) {
        if buf.capacity() > self.buf.capacity() {
            buf.clear();
            self.buf = buf;
        }
    }
}
