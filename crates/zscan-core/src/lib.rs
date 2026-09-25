//! zscan-core: find compressed streams inside arbitrary binary files, extract them,
//! and reinject edited versions.
//!
//! The typical flow is [`input::open`] → [`scan()`] → [`Manifest::new`] → [`extract_all`],
//! then after editing: [`load_edits`] → [`pack()`].
//! Front ends (CLI, GUI) call this library directly.

pub mod checksum;
pub mod codec;
pub mod codecs;
pub mod deflater;
pub mod entropy;
pub mod error;
pub mod extract;
pub mod input;
pub mod manifest;
pub mod pack;
pub mod scan;

pub use codec::{Codec, CompressionParams, DecodeCtx, DecodeError, Decoded, Format, Strategy, codec_for};
pub use deflater::DeflateParams;
pub use error::{Error, Result};
pub use extract::{ExtractOptions, ExtractedFile, decode_stream, extract_all};
pub use manifest::{Manifest, SourceInfo, StreamEntry};
pub use pack::{Outcome, PackOptions, PackResult, StreamPlan, load_edits, pack};
pub use scan::{FoundStream, ScanOptions, ScanStats, scan, scan_with_stats};
