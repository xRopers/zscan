//! Encoder settings, one typed struct per encoder library.
//!
//! A stream's `exact_params` are settings that, fed to that format's
//! [`Codec::encode`](crate::codec::Codec::encode) together with the original stream,
//! reproduce it byte for byte. Each codec also derives default settings from a stream's
//! header when no exact match is known.

use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::deflater::{DeflateParams, Strategy};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoder", rename_all = "lowercase")]
pub enum EncoderParams {
    /// zlib's deflate, used for gzip, zlib and raw deflate streams.
    Deflate(DeflateParams),
    Zstd(ZstdParams),
    Xz(XzParams),
    Bzip2(Bzip2Params),
    Lz4(Lz4Params),
    Brotli(BrotliParams),
}

impl EncoderParams {
    pub fn as_deflate(&self) -> Option<&DeflateParams> {
        match self {
            EncoderParams::Deflate(p) => Some(p),
            _ => None,
        }
    }
}

impl fmt::Display for EncoderParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncoderParams::Deflate(p) => p.fmt(f),
            EncoderParams::Zstd(p) => {
                write!(f, "L{}", p.level)?;
                if p.checksum {
                    f.write_str(" +checksum")?;
                }
                if !p.content_size {
                    f.write_str(" -size")?;
                }
                Ok(())
            }
            EncoderParams::Xz(p) => {
                write!(f, "{}{} {:?} D{}K", p.preset, if p.extreme { "e" } else { "" }, p.check, p.dict_size / 1024)?;
                if p.threaded {
                    f.write_str(" mt")?;
                }
                Ok(())
            }
            EncoderParams::Bzip2(p) => write!(f, "{}", p.level),
            EncoderParams::Lz4(p) => write!(
                f,
                "B{}K {}{}{}{}",
                p.block_size / 1024,
                if p.independent_blocks { "indep" } else { "linked" },
                if p.block_checksums { " +bcrc" } else { "" },
                if p.content_checksum { " +crc" } else { "" },
                if p.content_size { " +size" } else { "" },
            ),
            EncoderParams::Brotli(p) => write!(f, "Q{} W{} {:?}", p.quality, p.lgwin, p.mode),
        }
    }
}

/// libzstd settings. `checksum` and `content_size` are frame header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZstdParams {
    pub level: i32,
    pub checksum: bool,
    pub content_size: bool,
}

/// liblzma "easy" presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XzParams {
    /// 0-9.
    pub preset: u32,
    pub extreme: bool,
    pub check: XzCheck,
    /// LZMA2 dictionary size. Presets imply one, but the xz tool shrinks it for small
    /// inputs, so it is read from the stream's block header instead.
    pub dict_size: u32,
    /// Made by liblzma's multithreaded encoder (xz -T), which writes block sizes into
    /// block headers. Its output doesn't depend on the thread count.
    pub threaded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XzCheck {
    None,
    Crc32,
    Crc64,
    Sha256,
}

/// libbzip2 block size level, 1-9 (100-900 kB). The work factor only picks a sorting
/// algorithm and never changes the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bzip2Params {
    pub level: u32,
}

/// LZ4 frame settings for the lz4_flex encoder, which has a single compression level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lz4Params {
    /// Maximum block size in bytes: 64 KiB, 256 KiB, 1 MiB, 4 MiB or 8 MiB.
    pub block_size: u32,
    pub independent_blocks: bool,
    pub block_checksums: bool,
    pub content_checksum: bool,
    pub content_size: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrotliParams {
    /// 0-11.
    pub quality: u32,
    /// Window size exponent, 10-24.
    pub lgwin: u32,
    pub mode: BrotliMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrotliMode {
    Generic,
    Text,
    Font,
}
