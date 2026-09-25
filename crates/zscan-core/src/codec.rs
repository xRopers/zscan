//! The [`Codec`] trait and the types shared by every stream format.

use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
use serde::{Deserialize, Serialize};

use crate::codecs::{BrotliCodec, Bzip2Codec, DeflateCodec, GzipCodec, Lz4Codec, XzCodec, ZlibCodec, ZstdCodec};
use crate::params::EncoderParams;
use crate::plugins::Unavailable;

/// Compressed stream formats. Declaration order is scan priority: when two formats
/// match at the same offset, the earlier (better verified) one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// RFC 1952: header, deflate body, CRC-32 + size trailer.
    Gzip,
    /// RFC 1950: 2-byte header, deflate body, Adler-32 trailer.
    Zlib,
    /// Zstandard frame: 32-bit magic, optional XXH64 content checksum.
    Zstd,
    /// .xz stream: magic, CRC-protected headers, optional content check.
    Xz,
    /// bzip2 stream: `BZh` + level, 48-bit block magic, per-block CRC.
    Bzip2,
    /// LZ4 frame: 32-bit magic, header checksum, optional block/content checksums.
    Lz4,
    /// RFC 1951 raw deflate. No header or checksum, so the weakest evidence.
    Deflate,
    /// RFC 7932 brotli. No magic or checksum, and random bytes decode as brotli too
    /// readily, so it is never scanned for: decode it at a known offset with
    /// [`decode_at`](crate::scan::decode_at).
    Brotli,
    /// Raw LZO1X (cargo feature `lzo`). No header or checksum, only an end marker, and the
    /// start is ambiguous, so it is scanned for only when asked, and only where a field
    /// just before the stream holds its compressed size.
    Lzo,
    /// Oodle Kraken, Mermaid, Selkie, Leviathan or Hydra (cargo feature `oodle`), decoded
    /// by the user's own oo2core library. Decoding needs the decompressed size, so it is
    /// scanned for only when asked, with sizes read from fields just before each candidate.
    Oodle,
}

impl Format {
    pub const ALL: [Format; 10] = [
        Format::Gzip,
        Format::Zlib,
        Format::Zstd,
        Format::Xz,
        Format::Bzip2,
        Format::Lz4,
        Format::Deflate,
        Format::Brotli,
        Format::Lzo,
        Format::Oodle,
    ];

    /// The formats a scan looks for by default. LZO and Oodle can be scanned for too, when
    /// asked; brotli never is (see [`Format::scannable`]).
    pub const SCANNABLE: [Format; 7] =
        [Format::Gzip, Format::Zlib, Format::Zstd, Format::Xz, Format::Bzip2, Format::Lz4, Format::Deflate];

    /// gzip, zlib and raw deflate: the formats whose body is a raw deflate stream.
    pub fn is_deflate_family(self) -> bool {
        matches!(self, Format::Gzip | Format::Zlib | Format::Deflate)
    }

    /// Whether a scan may look for this format at all. Brotli can't be scanned for: random
    /// bytes decode as brotli too readily.
    pub fn scannable(self) -> bool {
        self != Format::Brotli
    }

    /// Whether this build (and for Oodle, the configured library) can handle the format.
    pub fn available(self) -> Result<(), Unavailable> {
        codec_for(self).map(|_| ())
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Gzip => "gzip",
            Format::Zlib => "zlib",
            Format::Zstd => "zstd",
            Format::Xz => "xz",
            Format::Bzip2 => "bzip2",
            Format::Lz4 => "lz4",
            Format::Deflate => "deflate",
            Format::Brotli => "brotli",
            Format::Lzo => "lzo",
            Format::Oodle => "oodle",
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
            "zstd" | "zst" => Ok(Format::Zstd),
            "xz" => Ok(Format::Xz),
            "bzip2" | "bz2" => Ok(Format::Bzip2),
            "lz4" => Ok(Format::Lz4),
            "deflate" | "raw" => Ok(Format::Deflate),
            "brotli" | "br" => Ok(Format::Brotli),
            "lzo" | "lzo1x" => Ok(Format::Lzo),
            "oodle" => Ok(Format::Oodle),
            other => Err(format!(
                "unknown format '{other}' (expected one of gzip, zlib, zstd, xz, bzip2, lz4, deflate, brotli, lzo, oodle)"
            )),
        }
    }
}

/// A successfully decoded stream.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Bytes the whole stream occupies in the input, including header and trailer.
    pub compressed_size: usize,
    /// Where the compressed body sits within the stream: for the deflate family, the raw
    /// deflate data, with everything before it being header. Other formats use the
    /// whole stream.
    pub body: Range<usize>,
    pub data: Vec<u8>,
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
    #[error("the {0} size must be known (from a length field, or given by hand)")]
    SizeRequired(&'static str),
    #[error("decodes to {compressed} -> {decompressed} bytes, which disagrees with the sizes given")]
    SizeMismatch { compressed: usize, decompressed: usize },
    #[error("{0}")]
    Unavailable(String),
}

impl From<Unavailable> for DecodeError {
    fn from(e: Unavailable) -> Self {
        DecodeError::Unavailable(e.to_string())
    }
}

/// Sizes of a stream known from outside it: from the manifest, a length field or the
/// user. Formats that can't find their own end (Oodle) need these to decode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SizeHint {
    pub compressed: Option<usize>,
    pub decompressed: Option<usize>,
}

impl SizeHint {
    pub fn exact(compressed: usize, decompressed: usize) -> Self {
        Self { compressed: Some(compressed), decompressed: Some(decompressed) }
    }
}

/// One compressed stream format. Each format lives in its own file under `codecs/`.
pub trait Codec: Send + Sync {
    fn format(&self) -> Format;

    /// Whether the format carries its own integrity check (magic, header check and/or
    /// checksum). The scanner looks for these first, then for unverified formats (raw
    /// deflate, brotli) only in the gaps, under stricter filters.
    fn self_verifying(&self) -> bool;

    /// Cheap test on the first few bytes of `data`. May return false positives but
    /// must never reject a stream that `decode` would accept from a real encoder.
    fn probe(&self, data: &[u8]) -> bool;

    /// Decode a stream that starts at `data[0]`. `data` may extend past the stream end.
    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError>;

    /// [`Codec::decode`] with sizes known from outside the stream. Formats that find
    /// their own end ignore the hint; callers check the result against it.
    fn decode_with_hint(&self, data: &[u8], hint: SizeHint, ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let _ = hint;
        self.decode(data, ctx)
    }

    /// Whether decoding needs [`SizeHint::decompressed`]: [`Codec::decode`] alone fails
    /// with [`DecodeError::SizeRequired`]. The scanner then tries only sizes read from
    /// integer fields just before each candidate.
    fn needs_size(&self) -> bool {
        false
    }

    /// Whether a scan only accepts this format where an integer field in the 16 bytes
    /// before the stream holds its size: the decompressed size for formats that need it to
    /// decode (Oodle), otherwise the compressed size, which the scan then decodes exactly
    /// (raw LZO, whose start can't be told from its content, and which would be far too
    /// slow to decode at every offset).
    fn scan_needs_size_field(&self) -> bool {
        self.needs_size()
    }

    /// For unverified formats: how many bytes of `stream` count as evidence that it is
    /// real, compared against the raw minimum compressed size. Defaults to all of it.
    fn evidence(&self, stream: &[u8]) -> usize {
        stream.len()
    }

    /// Search for encoder settings with which [`Codec::encode`] reproduces `stream`
    /// (`decoded` is its decode) byte for byte.
    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams>;

    /// Settings for re-encoding when no exact match is known, taken from what the
    /// original stream's header says (window size, check type, flags...).
    fn default_params(&self, stream: &[u8], decoded: &Decoded) -> EncoderParams;

    /// Check recorded settings (e.g. from a hand-edited manifest) against this format
    /// and the original stream, adjusting them where the header constrains them
    /// (a zlib header's window size, for instance).
    fn adapt_params(&self, stream: &[u8], decoded: &Decoded, params: &EncoderParams) -> Result<EncoderParams, String>;

    /// Stronger settings to try when an edited stream doesn't fit its slot.
    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams>;

    /// Encode `data` as a complete stream to replace `stream`, reusing whatever header
    /// fields the format allows (a gzip file name, for instance). Deterministic: the same
    /// inputs always give the same bytes. Only encoders outside zscan (Oodle's library)
    /// can fail. Panics if `params` belong to another encoder; use
    /// [`Codec::adapt_params`] first on untrusted params.
    fn encode(&self, stream: &[u8], decoded: &Decoded, data: &[u8], params: &EncoderParams) -> Result<Vec<u8>, String>;
}

/// The codec implementation for a format. Fails for a plugin format this build doesn't
/// include, or for Oodle when its library can't be loaded; the error says how to fix it.
pub fn codec_for(format: Format) -> Result<&'static dyn Codec, Unavailable> {
    Ok(match format {
        Format::Gzip => &GzipCodec,
        Format::Zlib => &ZlibCodec,
        Format::Zstd => &ZstdCodec,
        Format::Xz => &XzCodec,
        Format::Bzip2 => &Bzip2Codec,
        Format::Lz4 => &Lz4Codec,
        Format::Deflate => &DeflateCodec,
        Format::Brotli => &BrotliCodec,
        Format::Lzo => crate::plugins::lzo()?,
        Format::Oodle => crate::plugins::oodle()?,
    })
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
            self.buf.resize(floor, 0);
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

    /// Copy the first `len` output bytes out of the context. Copying (rather than moving
    /// the buffer out) keeps the buffer initialised at full length, so later attempts
    /// never re-zero it. Scanning makes thousands of small decodes per MiB.
    pub(crate) fn take_output(&mut self, len: usize) -> Vec<u8> {
        self.buf[..len].to_vec()
    }
}
