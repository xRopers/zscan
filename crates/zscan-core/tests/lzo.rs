//! Raw LZO1X (cargo feature `lzo`): decoding at known offsets, opt-in scanning, exact
//! parameter matching, and the extract/pack round trip with length fields.
#![cfg(feature = "lzo")]

use std::collections::BTreeMap;
use std::path::Path;

use zscan_core::{
    DetectOptions, ExtractOptions, Format, Manifest, Measures, Outcome, PackOptions, ScanOptions, SizeHint, SourceInfo,
    apply_unambiguous, codec_for, decode_at, detect_fields, extract_all, pack, scan,
};
use zscan_fixtures::Fixture;

type Row = (u64, &'static str, u64, u64, u32);

fn expected_rows(f: &Fixture) -> Vec<Row> {
    f.expected
        .iter()
        .map(|e| (e.offset as u64, e.kind.as_str(), e.compressed_size as u64, e.payload.len() as u64, crc32fast::hash(&e.payload)))
        .collect()
}

fn with_lzo() -> ScanOptions {
    let mut opts = ScanOptions::default();
    opts.formats.push(Format::Lzo);
    opts
}

fn manifest_for(data: &[u8]) -> Manifest {
    let opts = with_lzo();
    let found = scan(data, &opts);
    Manifest::new(SourceInfo::describe(Path::new("lzo.bin"), data), opts, found)
}

#[test]
fn decodes_at_known_offsets_with_exact_params() {
    let f = zscan_fixtures::lzo_streams();
    let found: Vec<_> = f
        .expected
        .iter()
        .map(|e| decode_at(&f.data, e.offset as u64, Format::Lzo, SizeHint::default(), 1 << 30, true).unwrap())
        .collect();
    let rows: Vec<Row> = found.iter().map(|s| (s.offset, s.format.name(), s.compressed_size, s.decompressed_size, s.crc32)).collect();
    assert_eq!(rows, expected_rows(&f));

    let codec = codec_for(Format::Lzo).unwrap();
    let mut ctx = zscan_core::DecodeCtx::new(1 << 24);
    for (s, e) in found.iter().zip(&f.expected) {
        let params = s.exact_params.as_ref().unwrap_or_else(|| panic!("no exact params for the stream at {:#x}", e.offset));
        let original = &f.data[e.offset..e.offset + e.compressed_size];
        let decoded = codec.decode(original, &mut ctx).unwrap();
        assert!(codec.encode(original, &decoded, &e.payload, params).unwrap() == original, "{params} at {:#x}", e.offset);
    }
}

#[test]
fn scanning_is_opt_in() {
    let f = zscan_fixtures::lzo_streams();
    assert!(scan(&f.data, &ScanOptions::default()).is_empty(), "not in the default formats");
    let found = scan(&f.data, &with_lzo());
    let rows: Vec<Row> = found.iter().map(|s| (s.offset, s.format.name(), s.compressed_size, s.decompressed_size, s.crc32)).collect();
    assert_eq!(rows, expected_rows(&f));
    assert!(found.iter().all(|s| s.exact_params.is_some()));
}

#[test]
fn no_false_positives_in_the_other_fixtures() {
    for f in zscan_fixtures::all() {
        let lzo: Vec<_> = scan(&f.data, &with_lzo()).into_iter().filter(|s| s.format == Format::Lzo).collect();
        assert!(lzo.is_empty(), "fixture {}: {lzo:?}", f.name);
    }
}

#[test]
fn extract_edit_pack_round_trip_updates_size_fields() {
    let f = zscan_fixtures::lzo_streams();
    let mut manifest = manifest_for(&f.data);
    let candidates = detect_fields(&f.data, &manifest, &DetectOptions { window: 16, min_global_value: 1 << 20 });
    apply_unambiguous(&mut manifest, &candidates);
    for s in &manifest.streams {
        let kinds: Vec<_> = s.length_fields.iter().map(|l| (s.offset - l.offset, l.measures)).collect();
        assert_eq!(kinds, [(8, Measures::Decompressed), (4, Measures::Compressed)], "stream {}", s.id);
    }

    let dir = tempfile::tempdir().unwrap();
    let files = extract_all(&f.data, &manifest, dir.path(), &ExtractOptions::default()).unwrap();
    for (file, e) in files.iter().zip(&f.expected) {
        assert_eq!(std::fs::read(&file.path).unwrap(), e.payload);
    }

    // Edit two streams (LZO1X-1 and LZO1X-999), both shorter so they fit.
    let edit = |payload: &[u8], len: usize| {
        let mut e = payload[..len].to_vec();
        e[10..16].copy_from_slice(b"EDITED");
        e
    };
    let edits = BTreeMap::from([
        (manifest.streams[0].id, edit(&f.expected[0].payload, 15_000)),
        (manifest.streams[3].id, edit(&f.expected[3].payload, 30_000)),
    ]);
    let result = pack(&f.data, &manifest, &edits, &PackOptions::default()).unwrap();
    assert!(result.fits());
    for i in [0, 3] {
        let Outcome::Repacked { reused_original_params, .. } = &result.streams[i].outcome else { panic!("stream {i} not repacked") };
        assert!(reused_original_params, "stream {i}: the settings matched by the scan were reused");
    }
    assert_eq!(result.field_updates.len(), 4, "both sizes of both edited streams change");

    let out = result.apply(&f.data).unwrap();
    let packed = result.verify_output(&out).unwrap();
    // Each size field now describes its stream, and unedited streams are byte-identical.
    for (s, e) in packed.streams.iter().zip(&f.expected) {
        let at = s.offset as usize;
        let read = |o: usize| u64::from(u32::from_le_bytes(out[o..o + 4].try_into().unwrap()));
        assert_eq!((read(at - 8), read(at - 4)), (s.decompressed_size, s.compressed_size), "stream {}", s.id);
        if !edits.contains_key(&s.id) {
            assert!(out[at..at + e.compressed_size] == f.data[at..at + e.compressed_size]);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    for file in extract_all(&out, &packed, dir.path(), &ExtractOptions::default()).unwrap() {
        let expected = edits.get(&file.id).cloned().unwrap_or_else(|| f.expected[file.id as usize].payload.clone());
        assert_eq!(std::fs::read(&file.path).unwrap(), expected, "stream {}", file.id);
    }
}
