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
pub mod fields;
pub mod input;
pub mod manifest;
pub mod pack;
pub mod params;
pub mod scan;

pub use codec::{Codec, DecodeCtx, DecodeError, Decoded, Format, codec_for};
pub use params::{DeflateParams, EncoderParams, Strategy};
pub use error::{Error, Result};
pub use extract::{ExtractOptions, ExtractedFile, decode_stream, extract_all};
pub use manifest::{Manifest, SourceInfo, StreamEntry};
pub use fields::{DetectOptions, FieldCandidate, apply_unambiguous, check_fields, detect_fields};
pub use manifest::{Endian, LengthField, Measures};
pub use pack::{FieldUpdate, Outcome, PackOptions, PackResult, StreamPlan, load_edits, pack};
pub use scan::{FoundStream, ScanOptions, ScanStats, decode_at, scan, scan_with_stats};
