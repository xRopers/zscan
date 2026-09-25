//! One file per stream format.

pub mod deflate;
pub mod gzip;
pub mod zlib;

pub use deflate::DeflateCodec;
pub use gzip::GzipCodec;
pub use zlib::ZlibCodec;
