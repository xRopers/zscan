//! Length-field rules: fields elsewhere in a file that record a stream's compressed
//! size, decompressed size or offset (an archive directory, or a size prefix just before
//! the stream). Pack rewrites them when a stream changes, and they are what makes it
//! safe to move a stream that outgrows its slot.

use std::collections::{HashMap, HashSet};

use rayon::prelude::*;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::manifest::{Endian, LengthField, Manifest, Measures, StreamEntry};

impl LengthField {
    pub fn end(&self) -> u64 {
        self.offset + u64::from(self.width)
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.width, 1 | 2 | 4 | 8)
    }

    /// The value currently stored in `data`, or `None` if the field is out of bounds.
    pub fn read(&self, data: &[u8]) -> Option<u64> {
        let start = usize::try_from(self.offset).ok()?;
        let bytes = data.get(start..start.checked_add(usize::from(self.width))?)?;
        Some(read_uint(bytes, self.endian))
    }

    /// What the field must hold when the quantity it measures is `measured`, or `None`
    /// if that doesn't fit in the field.
    pub fn stored_value(&self, measured: u64) -> Option<u64> {
        let v = u64::try_from(i128::from(measured) + i128::from(self.adjust)).ok()?;
        (self.width >= 8 || v < 1 << (8 * u32::from(self.width))).then_some(v)
    }

    /// The field's bytes for a measured quantity, or `None` if it doesn't fit.
    pub fn encode(&self, measured: u64) -> Option<Vec<u8>> {
        let v = self.stored_value(measured)?;
        let w = usize::from(self.width);
        Some(match self.endian {
            Endian::Little => v.to_le_bytes()[..w].to_vec(),
            Endian::Big => v.to_be_bytes()[8 - w..].to_vec(),
        })
    }
}

fn read_uint(bytes: &[u8], endian: Endian) -> u64 {
    let mut buf = [0u8; 8];
    match endian {
        Endian::Little => {
            buf[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(buf)
        }
        Endian::Big => {
            buf[8 - bytes.len()..].copy_from_slice(bytes);
            u64::from_be_bytes(buf)
        }
    }
}

/// The quantity a field of kind `m` records for `entry`.
pub fn measure(entry: &StreamEntry, m: Measures) -> u64 {
    match m {
        Measures::Compressed => entry.compressed_size,
        Measures::Decompressed => entry.decompressed_size,
        Measures::Offset => entry.offset,
    }
}

pub(crate) fn measure_name(m: Measures) -> &'static str {
    match m {
        Measures::Compressed => "compressed-size",
        Measures::Decompressed => "decompressed-size",
        Measures::Offset => "offset",
    }
}

/// Check every field in `manifest` against `data`: a valid width, in bounds, not inside
/// any stream or another field, and holding the value it should.
pub fn check_fields(data: &[u8], manifest: &Manifest) -> Result<()> {
    let mut spans = Vec::new();
    for entry in &manifest.streams {
        for f in &entry.length_fields {
            let what = || format!("stream {} {} field at {:#x}", entry.id, measure_name(f.measures), f.offset);
            if !f.is_valid() {
                return Err(Error::InvalidManifest(format!("{}: width {} is not 1, 2, 4 or 8", what(), f.width)));
            }
            if let Some(s) = manifest.streams.iter().find(|s| f.offset < s.end() && s.offset < f.end()) {
                return Err(Error::InvalidManifest(format!("{} lies inside stream {}", what(), s.id)));
            }
            let actual = f.read(data).ok_or_else(|| Error::InvalidManifest(format!("{} is past the end of the file", what())))?;
            match f.stored_value(measure(entry, f.measures)) {
                Some(expected) if expected == actual => {}
                Some(expected) => {
                    return Err(Error::InvalidManifest(format!("{} holds {actual}, expected {expected}", what())));
                }
                None => return Err(Error::InvalidManifest(format!("{}: the value doesn't fit its width", what()))),
            }
            spans.push((f.offset, f.end(), entry.id));
        }
    }
    spans.sort_unstable();
    if let Some(w) = spans.windows(2).find(|w| w[0].1 > w[1].0) {
        return Err(Error::InvalidManifest(format!(
            "fields at {:#x} (stream {}) and {:#x} (stream {}) overlap",
            w[0].0, w[0].2, w[1].0, w[1].2
        )));
    }
    Ok(())
}

/// Where [`detect_fields`] looks, and how cautiously.
#[derive(Debug, Clone)]
pub struct DetectOptions {
    /// Bytes before each stream searched for size fields of any value (a size prefix).
    pub window: u64,
    /// Elsewhere in the file, only values at least this large are considered: small
    /// numbers turn up everywhere by chance.
    pub min_global_value: u64,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self { window: 64, min_global_value: 65_536 }
    }
}

/// A place in the file that holds one of a stream's sizes or its offset.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldCandidate {
    pub stream_id: u32,
    pub field: LengthField,
    /// Found in the window just before the stream, rather than elsewhere in the file.
    pub near: bool,
}

/// Look for fields holding each stream's compressed size, decompressed size or offset:
/// 2-, 4- and 8-byte integers of either byte order, just before the stream (any value)
/// or anywhere outside streams (large values only). Where several widths match at one
/// spot (a u32 followed by zero bytes also reads as a u64), 4 bytes wins, then 8, then 2.
pub fn detect_fields(data: &[u8], manifest: &Manifest, opts: &DetectOptions) -> Vec<FieldCandidate> {
    let mut streams: Vec<&StreamEntry> = manifest.streams.iter().collect();
    streams.sort_by_key(|s| s.offset);
    let inside_stream = |start: u64, end: u64| streams.iter().any(|s| start < s.end() && s.offset < end);

    let mut found: Vec<FieldCandidate> = Vec::new();
    let mut push = |c: FieldCandidate| {
        if !found.iter().any(|f| f.stream_id == c.stream_id && f.field == c.field) {
            found.push(c);
        }
    };

    // Near: any value, just before each stream.
    for s in &streams {
        let from = s.offset.saturating_sub(opts.window);
        for pos in from..s.offset {
            for width in [2u8, 4, 8] {
                for endian in [Endian::Little, Endian::Big] {
                    let mut field = LengthField { offset: pos, width, endian, measures: Measures::Compressed, adjust: 0 };
                    if field.end() > s.offset || inside_stream(pos, field.end()) {
                        continue;
                    }
                    let Some(v) = field.read(data) else { continue };
                    for m in [Measures::Compressed, Measures::Decompressed] {
                        if v != 0 && v == measure(s, m) {
                            field.measures = m;
                            push(FieldCandidate { stream_id: s.id, field, near: true });
                        }
                    }
                }
            }
        }
    }

    // Global: large values anywhere outside streams.
    let mut targets: HashMap<u64, Vec<(u32, Measures)>> = HashMap::new();
    for s in &streams {
        for m in [Measures::Compressed, Measures::Decompressed, Measures::Offset] {
            let v = measure(s, m);
            if v >= opts.min_global_value {
                targets.entry(v).or_default().push((s.id, m));
            }
        }
    }
    // A 64K-bit filter on the low 16 bits rejects almost every position cheaply.
    let mut filter = vec![0u64; 1024];
    for &v in targets.keys() {
        filter[(v as usize & 0xffff) >> 6] |= 1 << (v & 63);
    }
    let maybe = |v: u64| filter[(v as usize & 0xffff) >> 6] & (1 << (v & 63)) != 0;
    let mut gaps = Vec::new();
    let mut pos = 0;
    for s in &streams {
        if s.offset > pos {
            gaps.push((pos as usize, s.offset as usize));
        }
        pos = pos.max(s.end());
    }
    gaps.push((pos as usize, data.len()));
    let chunks: Vec<(usize, usize, usize)> = gaps
        .iter()
        .flat_map(|&(start, end)| (start..end).step_by(1 << 20).map(move |c| (c, (c + (1 << 20)).min(end), end)))
        .collect();
    let hits: Vec<(u64, u8, Endian, u64)> = chunks
        .par_iter()
        .flat_map_iter(|&(from, to, gap_end)| {
            let mut out = Vec::new();
            for p in from..to {
                for width in [4usize, 8] {
                    let Some(bytes) = data.get(p..p + width).filter(|_| p + width <= gap_end) else { continue };
                    for endian in [Endian::Little, Endian::Big] {
                        let v = read_uint(bytes, endian);
                        if maybe(v) && targets.contains_key(&v) {
                            out.push((p as u64, width as u8, endian, v));
                        }
                    }
                }
            }
            out
        })
        .collect();
    for (offset, width, endian, v) in hits {
        for &(stream_id, measures) in &targets[&v] {
            let field = LengthField { offset, width, endian, measures, adjust: 0 };
            push(FieldCandidate { stream_id, field, near: false });
        }
    }

    prefer_widths(found)
}

/// Among candidates for the same stream, quantity and byte order whose bytes overlap,
/// keep only the preferred width (4, then 8, then 2).
fn prefer_widths(mut found: Vec<FieldCandidate>) -> Vec<FieldCandidate> {
    let rank = |w: u8| match w {
        4 => 0,
        8 => 1,
        _ => 2,
    };
    found.sort_by_key(|c| (c.stream_id, c.field.offset, rank(c.field.width)));
    let mut kept: Vec<FieldCandidate> = Vec::new();
    for c in found {
        let clash = kept.iter().any(|k| {
            k.stream_id == c.stream_id
                && k.field.measures == c.field.measures
                && k.field.endian == c.field.endian
                && k.field.offset < c.field.end()
                && c.field.offset < k.field.end()
        });
        if !clash {
            kept.push(c);
        }
    }
    kept.sort_by_key(|c| (c.stream_id, c.field.offset));
    kept
}

/// Add the unambiguous candidates to `manifest`: those at a location no other
/// candidate claims (two streams with the same size, say). A quantity may have several
/// fields: an archive often stores a size both in its directory and in front of the
/// data, and both must be kept up to date. Returns the candidates added.
pub fn apply_unambiguous(manifest: &mut Manifest, candidates: &[FieldCandidate]) -> Vec<FieldCandidate> {
    let mut per_location: HashMap<u64, usize> = HashMap::new();
    for c in candidates {
        *per_location.entry(c.field.offset).or_default() += 1;
    }
    let mut claimed: HashSet<u64> = manifest.streams.iter().flat_map(|s| s.length_fields.iter().map(|f| f.offset)).collect();
    let mut added = Vec::new();
    for c in candidates {
        if per_location[&c.field.offset] != 1 || claimed.contains(&c.field.offset) {
            continue;
        }
        let Some(entry) = manifest.streams.iter_mut().find(|s| s.id == c.stream_id) else { continue };
        entry.length_fields.push(c.field);
        claimed.insert(c.field.offset);
        added.push(c.clone());
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(width: u8, endian: Endian, adjust: i64) -> LengthField {
        LengthField { offset: 1, width, endian, measures: Measures::Compressed, adjust }
    }

    #[test]
    fn read_and_encode() {
        let data = [0xff, 0x34, 0x12, 0x00, 0x00, 0xff];
        assert_eq!(field(2, Endian::Little, 0).read(&data), Some(0x1234));
        assert_eq!(field(4, Endian::Little, 0).read(&data), Some(0x1234));
        assert_eq!(field(2, Endian::Big, 0).read(&data), Some(0x3412));
        assert_eq!(field(8, Endian::Little, 0).read(&data), None, "out of bounds");
        assert_eq!(field(2, Endian::Big, 0).encode(0x3412), Some(vec![0x34, 0x12]));
        assert_eq!(field(2, Endian::Little, 0).encode(0x1_0000), None, "doesn't fit");
        assert_eq!(field(2, Endian::Little, -4).encode(0x1_0003), Some(vec![0xff, 0xff]));
        assert_eq!(field(4, Endian::Little, -10).encode(5), None, "negative");
        assert_eq!(field(8, Endian::Big, 0).encode(u64::MAX), Some(vec![0xff; 8]));
    }
}
