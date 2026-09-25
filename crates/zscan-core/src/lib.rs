//! zscan-core: find compressed streams inside arbitrary binary files, extract them,
//! and (from build stage 2) reinject edited versions.
//!
//! The typical flow is [`input::open`] → [`scan()`] → [`Manifest::new`] → [`extract_all`].
//! Front ends (CLI, GUI) call this library directly.

pub mod checksum;
pub mod codec;
pub mod codecs;
pub mod entropy;
pub mod error;
pub mod extract;
pub mod input;
pub mod manifest;
pub mod scan;

pub use codec::{Codec, CompressionParams, DecodeCtx, DecodeError, Decoded, Format, Strategy, codec_for};
pub use error::{Error, Result};
pub use extract::{ExtractOptions, ExtractedFile, decode_stream, extract_all};
pub use manifest::{Manifest, SourceInfo, StreamEntry};
pub use scan::{FoundStream, ScanOptions, scan};
