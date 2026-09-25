//! Scan and extract every fixture; streams must be reported at exactly the known offsets.

use std::path::Path;

use zscan_core::deflater::compress_raw;
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
fn matched_params_rebuild_zlib_made_streams_exactly() {
    let mut ctx = DecodeCtx::new(1 << 24);
    for f in zscan_fixtures::all() {
        for (s, e) in scan(&f.data, &ScanOptions::default()).iter().zip(&f.expected) {
            let what = format!("fixture {} stream at {:#x}", f.name, e.offset);
            assert_eq!(s.params.exact_match, e.zlib_made, "{what}");
            let Some(params) = s.params.deflate_params().filter(|_| s.params.exact_match) else { continue };
            let original = &f.data[e.offset..e.offset + e.compressed_size];
            let codec = codec_for(s.format);
            let header = &original[..codec.decode(original, &mut ctx).unwrap().body.start];
            let rebuilt = codec.wrap(header, &compress_raw(&e.payload, &params), &e.payload);
            assert!(rebuilt == original, "{what}: {params} does not rebuild it");
        }
    }
}

#[test]
fn matching_can_be_turned_off() {
    let f = zscan_fixtures::zlib_basic();
    let opts = ScanOptions { match_params: false, ..Default::default() };
    assert!(scan(&f.data, &opts).iter().all(|s| !s.params.exact_match && s.params.level.is_none()));
}

#[test]
fn gzip_names_and_zlib_window_bits_are_recorded() {
    let f = zscan_fixtures::gzip_basic();
    let names: Vec<_> = scan(&f.data, &ScanOptions::default()).into_iter().map(|s| s.original_name).collect();
    let expected: Vec<_> = f.expected.iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, expected);

    let f = zscan_fixtures::zlib_basic();
    let bits: Vec<_> = scan(&f.data, &ScanOptions::default()).into_iter().map(|s| s.params.window_bits).collect();
    assert_eq!(bits, [Some(15), Some(15), Some(15), Some(15), Some(12), Some(15)]);
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
    let stored_ok = ScanOptions { raw_max_entropy: None, raw_min_ratio: 0.0, ..Default::default() };
    assert_eq!(offsets(stored_ok), [offset]);
    // Either stored-content rule alone rejects it.
    assert!(offsets(ScanOptions { raw_max_entropy: None, ..Default::default() }).is_empty());
    assert!(offsets(ScanOptions { raw_min_ratio: 0.0, ..Default::default() }).is_empty());
    assert_eq!(offsets(ScanOptions { raw_min_compressed: 100, ..Default::default() }), [small_offset]);
}

#[test]
fn stored_raw_deflate_needs_ratio_filter_off() {
    let f = zscan_fixtures::deflate_raw();
    let found = |opts: ScanOptions| scan(&f.data, &opts).len();
    assert_eq!(found(ScanOptions::default()), f.expected.len());
    assert_eq!(found(ScanOptions { raw_min_ratio: 0.0, ..Default::default() }), f.expected.len() + 1);
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
    for (k, f) in [(Kind::Gzip, Format::Gzip), (Kind::Zlib, Format::Zlib), (Kind::Deflate, Format::Deflate)] {
        assert_eq!(k.as_str(), f.name());
        assert_eq!(serde_json::to_string(&f).unwrap(), format!("\"{}\"", k.as_str()));
    }
}
