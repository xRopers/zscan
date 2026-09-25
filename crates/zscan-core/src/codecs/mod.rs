//! One file per stream format.

pub mod brotli;
pub mod bzip2;
pub mod deflate;
pub mod gzip;
pub mod lz4;
mod util;
pub mod xz;
pub mod zlib;
pub mod zstd;

pub use brotli::BrotliCodec;
pub use bzip2::Bzip2Codec;
pub use deflate::DeflateCodec;
pub use gzip::GzipCodec;
pub use lz4::Lz4Codec;
pub use xz::XzCodec;
pub use zlib::ZlibCodec;
pub use zstd::ZstdCodec;
