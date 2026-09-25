//! Scan and extract every fixture; streams must be reported at exactly the known offsets.

use std::path::Path;

use zscan_core::{
    DecodeCtx, Error, ExtractOptions, Format, Manifest, ScanOptions, SourceInfo, codec_for, decode_stream, extract_all,
    scan,
};
use zscan_fixtures::{Fixture, Kind};

type Row = (u64, &'static str, u64, u64, u32);

fn expected_rows(f: &Fixture) -> Vec<Row> {
    f.expected
        .iter()
        .map(|e| {
            (e.offset as u64, e.kind.as_str(), e.compressed_size as u64, e.payload.len() as u64, crc32fast::hash(&e.payload))
        })
        .collect()
}

fn found_rows(data: &[u8], opts: &ScanOptions) -> Vec<Row> {
    scan(data, opts)
        .iter()
        .map(|s| (s.offset, s.format.name(), s.compressed_size, s.decompressed_size, s.crc32))
        .collect()
}

fn manifest_for(f: &Fixture) -> Manifest {
    let opts = ScanOptions::default();
    let found = scan(&f.data, &opts);
    Manifest::new(SourceInfo::describe(Path::new(f.name), &f.data), opts, found)
}

#[test]
fn every_fixture_scans_exactly() {
    for f in zscan_fixtures::all() {
        assert_eq!(found_rows(&f.data, &ScanOptions::default()), expected_rows(&f), "fixture {}", f.name);
    }
}

#[test]
fn matched_params_rebuild_reproducible_streams_exactly() {
    let mut ctx = DecodeCtx::new(1 << 24);
    for f in zscan_fixtures::all() {
        for (s, e) in scan(&f.data, &ScanOptions::default()).iter().zip(&f.expected) {
            let what = format!("fixture {} stream at {:#x}", f.name, e.offset);
            assert_eq!(s.exact_params.is_some(), e.reproducible, "{what}");
            let Some(params) = &s.exact_params else { continue };
            let original = &f.data[e.offset..e.offset + e.compressed_size];
            let codec = codec_for(s.format);
            let decoded = codec.decode(original, &mut ctx).unwrap();
            let rebuilt = codec.encode(original, &decoded, &e.payload, params);
            assert!(rebuilt == original, "{what}: {params} does not rebuild it");
        }
    }
}

#[test]
fn matching_can_be_turned_off() {
    let f = zscan_fixtures::zlib_basic();
    let opts = ScanOptions { match_params: false, ..Default::default() };
    assert!(scan(&f.data, &opts).iter().all(|s| s.exact_params.is_none()));
}

#[test]
fn gzip_names_and_zlib_window_bits_are_recorded() {
    let f = zscan_fixtures::gzip_basic();
    let names: Vec<_> = scan(&f.data, &ScanOptions::default()).into_iter().map(|s| s.original_name).collect();
    let expected: Vec<_> = f.expected.iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, expected);

    let f = zscan_fixtures::zlib_basic();
    let bits: Vec<_> = scan(&f.data, &ScanOptions::default())
        .into_iter()
        .map(|s| s.exact_params.and_then(|p| p.as_deflate().map(|d| d.window_bits)))
        .collect();
    // The miniz-made stream has no exact params.
    assert_eq!(bits, [Some(15), Some(15), Some(15), Some(15), Some(12), None]);
}

#[test]
fn format_selection() {
    let f = zscan_fixtures::mixed();
    let opts = ScanOptions { formats: vec![Format::Zlib], ..Default::default() };
    let found = scan(&f.data, &opts);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].offset as usize, f.expected[0].offset);
}

#[test]
fn size_ratio_and_entropy_filters() {
    let f = zscan_fixtures::zlib_basic();
    // The stored (level 0) stream of 100 bytes has ratio < 1.
    let opts = ScanOptions { min_ratio: 1.0, ..Default::default() };
    assert_eq!(scan(&f.data, &opts).len(), f.expected.len() - 1);

    let opts = ScanOptions { min_size: 3001, ..Default::default() };
    assert_eq!(scan(&f.data, &opts).len(), 3, "only the 4000, 5000 and 20000 byte payloads remain");

    // Text payloads are ~4 bits/byte; records are lower.
    let opts = ScanOptions { max_entropy: Some(1.0), ..Default::default() };
    assert!(scan(&f.data, &opts).is_empty());

    // The tiny zlib trap in `mixed` is real; lowering min_size finds it.
    let m = zscan_fixtures::mixed();
    let opts = ScanOptions { min_size: 1, ..Default::default() };
    assert_eq!(scan(&m.data, &opts).len(), m.expected.len() + 1);
}

#[test]
fn raw_deflate_filters() {
    let mut rng = zscan_fixtures::Rng::new(7);
    let mut data = rng.bytes(300);
    let offset = data.len() as u64;
    // Stored raw deflate of random bytes: real, but indistinguishable from noise.
    data.extend(zscan_fixtures::deflate(&rng.bytes(5000), 0));
    // Short raw deflate: below the compressed-size threshold.
    let small = zscan_fixtures::text(&mut rng, 400);
    let small_offset = data.len() as u64;
    data.extend(zscan_fixtures::deflate(&small, 6));
    data.extend(rng.bytes(300));

    assert!(scan(&data, &ScanOptions::default()).is_empty());

    let offsets = |opts: ScanOptions| scan(&data, &opts).iter().map(|s| s.offset).collect::<Vec<_>>();
    // With all three stored-content rules off it is found (along with random-filler
    // garbage, which is what those rules are for); each rule alone rejects it.
    let stored_ok = ScanOptions { raw_max_entropy: None, raw_min_ratio: 0.0, raw_min_compressed: 0, ..Default::default() };
    assert!(offsets(stored_ok.clone()).contains(&offset));
    assert!(!offsets(ScanOptions { raw_max_entropy: Some(7.5), ..stored_ok.clone() }).contains(&offset));
    assert!(!offsets(ScanOptions { raw_min_ratio: 1.1, ..stored_ok.clone() }).contains(&offset));
    assert!(!offsets(ScanOptions { raw_min_compressed: 256, ..stored_ok }).contains(&offset));
    assert_eq!(offsets(ScanOptions { raw_min_compressed: 100, ..Default::default() }), [small_offset]);
}

#[test]
fn stored_raw_deflate_needs_ratio_filter_off() {
    let f = zscan_fixtures::deflate_raw();
    let found = |opts: ScanOptions| scan(&f.data, &opts).len();
    assert_eq!(found(ScanOptions::default()), f.expected.len());
    // The fixture's level-0 stream stores 1000 bytes in one block (5 bytes of header).
    let level0 = ScanOptions { raw_min_ratio: 0.0, raw_min_compressed: 0, ..Default::default() };
    let known: Vec<u64> = f.expected.iter().map(|e| e.offset as u64).collect();
    let extra: Vec<_> = scan(&f.data, &level0).into_iter().filter(|s| !known.contains(&s.offset)).collect();
    assert!(extra.iter().any(|s| s.decompressed_size == 1000 && s.compressed_size == 1005), "{extra:?}");
    // Lowering only one of the two limits isn't enough.
    let ratio_only = ScanOptions { raw_min_ratio: 0.0, ..Default::default() };
    assert_eq!(found(ratio_only), f.expected.len());
}

#[test]
fn raw_scan_does_not_steal_checksummed_streams() {
    // A raw-deflate candidate starting before a zlib stream must never hide it:
    // zlib is found first, raw deflate only looks in the gaps.
    let f = zscan_fixtures::zlib_basic();
    for s in scan(&f.data, &ScanOptions::default()) {
        assert_eq!(s.format, Format::Zlib);
    }
}

#[test]
fn extract_round_trip_through_json_manifest() {
    for f in zscan_fixtures::all() {
        let manifest = Manifest::from_json(&manifest_for(&f).to_json()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let files = extract_all(&f.data, &manifest, dir.path(), &ExtractOptions::default()).unwrap();
        assert_eq!(files.len(), f.expected.len(), "fixture {}", f.name);
        for (file, exp) in files.iter().zip(&f.expected) {
            assert_eq!(std::fs::read(&file.path).unwrap(), exp.payload, "fixture {} stream {}", f.name, file.id);
        }
    }
}

#[test]
fn extract_uses_gzip_names() {
    let f = zscan_fixtures::gzip_basic();
    let dir = tempfile::tempdir().unwrap();
    let files = extract_all(&f.data, &manifest_for(&f), dir.path(), &ExtractOptions::default()).unwrap();
    let name = files[0].path.file_name().unwrap().to_str().unwrap();
    assert_eq!(name, format!("{:08x}_hello.txt", f.expected[0].offset));
}

#[test]
fn extract_rejects_modified_input() {
    let f = zscan_fixtures::zlib_basic();
    let manifest = manifest_for(&f);
    let mut data = f.data.clone();
    // Flip a byte inside the first stream's deflate body.
    data[f.expected[0].offset + 10] ^= 0x55;
    let dir = tempfile::tempdir().unwrap();

    let err = extract_all(&data, &manifest, dir.path(), &ExtractOptions::default()).unwrap_err();
    assert!(matches!(err, Error::SourceMismatch(_)), "{err}");

    // Even with the source check off, the per-stream checks catch it.
    let err = extract_all(&data, &manifest, dir.path(), &ExtractOptions { verify_source: false }).unwrap_err();
    assert!(matches!(err, Error::Stream { id: 0, .. }), "{err}");
}

#[test]
fn extract_rejects_path_traversal() {
    let f = zscan_fixtures::zlib_basic();
    let mut manifest = manifest_for(&f);
    manifest.streams[1].file = "../escape.dat".into();
    let dir = tempfile::tempdir().unwrap();
    let err = extract_all(&f.data, &manifest, dir.path(), &ExtractOptions::default()).unwrap_err();
    assert!(matches!(err, Error::BadFilename(_)));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "nothing written before validation");
}

#[test]
fn decode_stream_checks_manifest_values() {
    let f = zscan_fixtures::gzip_basic();
    let mut manifest = manifest_for(&f);
    let mut ctx = DecodeCtx::new(1 << 20);
    assert!(decode_stream(&f.data, &manifest.streams[0], &mut ctx).is_ok());
    manifest.streams[0].crc32 ^= 1;
    assert!(decode_stream(&f.data, &manifest.streams[0], &mut ctx).is_err());
    manifest.streams[0].offset = u64::MAX;
    assert!(decode_stream(&f.data, &manifest.streams[0], &mut ctx).is_err());
}

#[test]
fn empty_and_tiny_inputs() {
    assert!(scan(&[], &ScanOptions::default()).is_empty());
    assert!(scan(&[0x78], &ScanOptions::default()).is_empty());
    assert!(scan(&[0x78, 0x9c], &ScanOptions::default()).is_empty());
    assert!(scan(&[0x1f, 0x8b, 0x08], &ScanOptions::default()).is_empty());
}

#[test]
fn kind_spelling_matches_format() {
    for (k, f) in [
        (Kind::Gzip, Format::Gzip),
        (Kind::Zlib, Format::Zlib),
        (Kind::Zstd, Format::Zstd),
        (Kind::Xz, Format::Xz),
        (Kind::Bzip2, Format::Bzip2),
        (Kind::Lz4, Format::Lz4),
        (Kind::Deflate, Format::Deflate),
        (Kind::Brotli, Format::Brotli),
    ] {
        assert_eq!(k.as_str(), f.name());
        assert_eq!(serde_json::to_string(&f).unwrap(), format!("\"{}\"", k.as_str()));
    }
}

#[test]
fn brotli_is_never_scanned_but_decodes_at_known_offsets() {
    let f = zscan_fixtures::brotli_streams();
    assert!(scan(&f.data, &ScanOptions::default()).is_empty());
    let opts = ScanOptions { formats: vec![Format::Brotli], ..Default::default() };
    assert!(scan(&f.data, &opts).is_empty(), "brotli is ignored even when asked for");

    let found: Vec<_> =
        f.expected.iter().map(|e| zscan_core::decode_at(&f.data, e.offset as u64, Format::Brotli, 1 << 30, true).unwrap()).collect();
    let rows: Vec<Row> = found.iter().map(|s| (s.offset, s.format.name(), s.compressed_size, s.decompressed_size, s.crc32)).collect();
    assert_eq!(rows, expected_rows(&f));
    let mut ctx = DecodeCtx::new(1 << 24);
    for (s, e) in found.iter().zip(&f.expected) {
        let params = s.exact_params.as_ref().unwrap_or_else(|| panic!("no exact params for brotli at {:#x}", e.offset));
        let original = &f.data[e.offset..e.offset + e.compressed_size];
        let decoded = codec_for(Format::Brotli).decode(original, &mut ctx).unwrap();
        assert!(codec_for(Format::Brotli).encode(original, &decoded, &e.payload, params) == original);
    }
}

#[test]
fn decode_at_and_add_stream() {
    let f = zscan_fixtures::zlib_basic();
    let mut manifest = manifest_for(&f);
    // Drop a scanned stream and add it back by hand.
    let removed = manifest.streams.remove(2);
    let found = zscan_core::decode_at(&f.data, removed.offset, Format::Zlib, 1 << 30, true).unwrap();
    assert_eq!((found.compressed_size, found.crc32), (removed.compressed_size, removed.crc32));
    assert_eq!(found.exact_params, removed.exact_params);
    let id = manifest.add_stream(found.clone()).unwrap();
    assert_eq!(id, 6, "ids 0,1,3,4,5 remain, so the next free id is 6");
    assert_eq!(manifest.streams[2].offset, removed.offset, "kept in offset order");
    assert!(matches!(manifest.add_stream(found), Err(Error::InvalidManifest(_))), "overlap rejected");
    // Wrong format or offset fails cleanly.
    assert!(zscan_core::decode_at(&f.data, removed.offset + 1, Format::Zlib, 1 << 30, false).is_err());
    assert!(zscan_core::decode_at(&f.data, u64::MAX, Format::Zlib, 1 << 30, false).is_err());
}

#[test]
fn every_format_parses_by_name() {
    for f in Format::ALL {
        assert_eq!(f.name().parse::<Format>().unwrap(), f);
        assert_eq!(serde_json::to_string(&f).unwrap(), format!("\"{}\"", f.name()));
    }
    assert!(!Format::SCANNABLE.contains(&Format::Brotli));
    assert!(Format::SCANNABLE.iter().all(|f| f.scannable()));
}
