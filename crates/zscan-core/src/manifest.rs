//! The manifest: what a scan found, and the contract that extract and pack work from.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::checksum::crc32;
use crate::codec::Format;
use crate::error::{Error, Result, io_err};
use crate::params::EncoderParams;
use crate::scan::{FoundStream, ScanOptions};

/// Version 2 replaced v1's deflate-only `params` with `exact_params`, tagged by encoder.
/// Version 1 manifests are migrated on load.
pub const MANIFEST_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub source: SourceInfo,
    pub scan_options: ScanOptions,
    pub streams: Vec<StreamEntry>,
}

/// Identifies the input file, so a manifest isn't applied to the wrong file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub path: String,
    pub size: u64,
    #[serde(with = "hex_u32")]
    pub crc32: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamEntry {
    pub id: u32,
    pub offset: u64,
    pub compressed_size: u64,
    pub decompressed_size: u64,
    pub format: Format,
    /// Settings that reproduce the stream exactly, if the scan found any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_params: Option<EncoderParams>,
    /// CRC-32 of the original decompressed data.
    #[serde(with = "hex_u32")]
    pub crc32: u32,
    /// Extracted file name, relative to the extract directory.
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub length_fields: Vec<LengthField>,
}

/// A field elsewhere in the file that records this stream's size.
/// Recorded only for now; pack starts honouring these in build stage 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LengthField {
    pub offset: u64,
    /// Width in bytes (1, 2, 4 or 8).
    pub width: u8,
    pub endian: Endian,
    pub measures: Measures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Measures {
    Compressed,
    Decompressed,
}

impl SourceInfo {
    pub fn describe(path: &Path, data: &[u8]) -> Self {
        Self { path: path.display().to_string(), size: data.len() as u64, crc32: crc32(data) }
    }

    /// Error if `data` is not the file this manifest was made from.
    pub fn check(&self, data: &[u8]) -> Result<()> {
        if data.len() as u64 != self.size {
            return Err(Error::SourceMismatch(format!(
                "input is {} bytes, manifest expects {}",
                data.len(),
                self.size
            )));
        }
        let actual = crc32(data);
        if actual != self.crc32 {
            return Err(Error::SourceMismatch(format!(
                "input CRC-32 is {actual:08x}, manifest expects {:08x}",
                self.crc32
            )));
        }
        Ok(())
    }
}

impl StreamEntry {
    pub fn end(&self) -> u64 {
        self.offset + self.compressed_size
    }

    pub fn ratio(&self) -> f64 {
        self.decompressed_size as f64 / self.compressed_size.max(1) as f64
    }
}

impl Manifest {
    pub fn new(source: SourceInfo, scan_options: ScanOptions, found: Vec<FoundStream>) -> Self {
        let streams = found
            .into_iter()
            .enumerate()
            .map(|(i, s)| StreamEntry {
                id: i as u32,
                file: stream_filename(s.offset, s.original_name.as_deref()),
                offset: s.offset,
                compressed_size: s.compressed_size,
                decompressed_size: s.decompressed_size,
                format: s.format,
                exact_params: s.exact_params,
                crc32: s.crc32,
                original_name: s.original_name,
                length_fields: Vec::new(),
            })
            .collect();
        Self { version: MANIFEST_VERSION, source, scan_options, streams }
    }

    /// Add a stream found outside a scan (e.g. by [`decode_at`](crate::scan::decode_at)).
    /// It gets the next free id. Errors if it overlaps a stream already listed.
    pub fn add_stream(&mut self, found: FoundStream) -> Result<u32> {
        if let Some(clash) = self.streams.iter().find(|s| found.offset < s.end() && s.offset < found.end()) {
            return Err(Error::InvalidManifest(format!(
                "a {} stream at {:#x} overlaps stream {} ({} at {:#x})",
                found.format, found.offset, clash.id, clash.format, clash.offset
            )));
        }
        let id = self.streams.iter().map(|s| s.id + 1).max().unwrap_or(0);
        let pos = self.streams.partition_point(|s| s.offset < found.offset);
        self.streams.insert(
            pos,
            StreamEntry {
                id,
                file: stream_filename(found.offset, found.original_name.as_deref()),
                offset: found.offset,
                compressed_size: found.compressed_size,
                decompressed_size: found.decompressed_size,
                format: found.format,
                exact_params: found.exact_params,
                crc32: found.crc32,
                original_name: found.original_name,
                length_fields: Vec::new(),
            },
        );
        Ok(id)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let mut value: serde_json::Value = serde_json::from_str(text)?;
        match value["version"].as_u64() {
            Some(1) => migrate_v1(&mut value),
            Some(v) if v == u64::from(MANIFEST_VERSION) => {}
            other => {
                let found = other.and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
                return Err(Error::ManifestVersion { found, expected: MANIFEST_VERSION });
            }
        }
        Ok(serde_json::from_value(value)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serialization cannot fail")
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::from_json(&fs::read_to_string(path).map_err(io_err(path))?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, self.to_json() + "\n").map_err(io_err(path))
    }
}

/// v1 streams had `params: {level, window_bits, mem_level, strategy, exact_match}`, always
/// zlib deflate settings. Keep them only when they were an exact match.
fn migrate_v1(manifest: &mut serde_json::Value) {
    if let Some(streams) = manifest["streams"].as_array_mut() {
        for stream in streams {
            let Some(obj) = stream.as_object_mut() else { continue };
            let Some(params) = obj.remove("params") else { continue };
            let complete = ["level", "window_bits", "mem_level", "strategy"].iter().all(|k| !params[*k].is_null());
            if params["exact_match"] == true && complete {
                let exact = serde_json::json!({
                    "encoder": "deflate",
                    "level": params["level"],
                    "window_bits": params["window_bits"],
                    "mem_level": params["mem_level"],
                    "strategy": params["strategy"],
                });
                obj.insert("exact_params".into(), exact);
            }
        }
    }
    manifest["version"] = MANIFEST_VERSION.into();
}

/// Output file name for a stream: `<offset>.dat`, or `<offset>_<name>` when the stream
/// header carries a file name (gzip FNAME).
pub fn stream_filename(offset: u64, original_name: Option<&str>) -> String {
    let name = original_name.map(sanitize).filter(|n| !n.is_empty());
    match name {
        Some(name) => format!("{offset:08x}_{name}"),
        None => format!("{offset:08x}.dat"),
    }
}

/// Keep only the last path component, restricted to a portable character set.
fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    clean.trim_start_matches('.').to_string()
}

/// True if `name` is a plain file name that can't escape the output directory.
pub fn is_safe_filename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', ':', '\0'])
}

mod hex_u32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &u32, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{value:08x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
        let text = String::deserialize(d)?;
        let digits = text.strip_prefix("0x").unwrap_or(&text);
        u32::from_str_radix(digits, 16).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames() {
        assert_eq!(stream_filename(0x1234, None), "00001234.dat");
        assert_eq!(stream_filename(0x10, Some("dir/../evil name.txt")), "00000010_evil_name.txt");
        assert_eq!(stream_filename(0x10, Some("..")), "00000010.dat");
        assert_eq!(stream_filename(0x1_0000_0000, None), "100000000.dat");
    }

    #[test]
    fn safe_filenames() {
        assert!(is_safe_filename("00001234.dat"));
        assert!(!is_safe_filename("../x"));
        assert!(!is_safe_filename("C:x"));
        assert!(!is_safe_filename(".."));
        assert!(!is_safe_filename(""));
    }

    #[test]
    fn migrates_v1_params() {
        let v1 = r#"{
          "version": 1,
          "source": { "path": "x", "size": 3, "crc32": "352441c2" },
          "scan_options": { "formats": ["zlib"], "min_size": 32, "raw_min_compressed": 256, "min_ratio": 0.0, "max_output": 1024 },
          "streams": [
            { "id": 0, "offset": 0, "compressed_size": 10, "decompressed_size": 20, "format": "zlib", "crc32": "00000001",
              "file": "a.dat", "params": { "level": 9, "window_bits": 15, "mem_level": 8, "strategy": "default", "exact_match": true } },
            { "id": 1, "offset": 10, "compressed_size": 10, "decompressed_size": 20, "format": "zlib", "crc32": "00000002",
              "file": "b.dat", "params": { "window_bits": 12, "exact_match": false } }
          ]
        }"#;
        let m = Manifest::from_json(v1).unwrap();
        assert_eq!(m.version, MANIFEST_VERSION);
        let expected = crate::params::DeflateParams { level: 9, window_bits: 15, mem_level: 8, strategy: crate::params::Strategy::Default };
        assert_eq!(m.streams[0].exact_params, Some(EncoderParams::Deflate(expected)));
        assert_eq!(m.streams[1].exact_params, None);
    }

    #[test]
    fn rejects_other_versions() {
        let m = Manifest::new(SourceInfo::describe(Path::new("x"), b"abc"), ScanOptions::default(), vec![]);
        let text = m.to_json().replace("\"version\": 2", "\"version\": 99");
        assert!(matches!(Manifest::from_json(&text), Err(Error::ManifestVersion { found: 99, .. })));
    }
}
