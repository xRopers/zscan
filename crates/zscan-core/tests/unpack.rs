//! Unpack and rebuild: every fixture must come back bit for bit, using the cheapest
//! method that works for each stream.

use std::fs;
use std::path::Path;

use zscan_core::{Error, Manifest, Method, ScanOptions, SourceInfo, UnpackIndex, rebuild, scan, unpack};
use zscan_fixtures::Fixture;

fn manifest_for(f: &Fixture) -> Manifest {
    let opts = ScanOptions::default();
    Manifest::new(SourceInfo::describe(Path::new(f.name), &f.data), opts.clone(), scan(&f.data, &opts))
}

fn index(dir: &Path) -> UnpackIndex {
    serde_json::from_str(&fs::read_to_string(dir.join("unpack.json")).unwrap()).unwrap()
}

fn method_kind(m: &Method) -> &'static str {
    match m {
        Method::Encode { .. } => "encode",
        Method::Preflate { .. } => "preflate",
        Method::Stored { .. } => "stored",
    }
}

#[test]
fn every_fixture_rebuilds_bit_for_bit() {
    for f in zscan_fixtures::all() {
        let dir = tempfile::tempdir().unwrap();
        let summary = unpack(&f.data, &manifest_for(&f), dir.path()).unwrap();
        assert_eq!(summary.streams, f.expected.len(), "fixture {}", f.name);
        let mut out = Vec::new();
        let rebuilt = rebuild(dir.path(), &mut out).unwrap();
        assert_eq!(rebuilt.bytes, f.data.len() as u64);
        assert!(out == f.data, "fixture {} differs after rebuild", f.name);
        // Contents are stored decompressed, as extract writes them.
        for (s, e) in index(dir.path()).streams.iter().zip(&f.expected) {
            assert_eq!(fs::read(dir.path().join("streams").join(&s.file)).unwrap(), e.payload);
        }
    }
}

#[test]
fn each_stream_gets_the_cheapest_exact_method() {
    // zlib_basic: five zlib-made streams and one made by miniz. zlib can't reproduce
    // that one, and preflate's predictor fails on it too (it can't find one of miniz's
    // matches, at any hash-chain length), so it is kept verbatim. Still exact.
    let f = zscan_fixtures::zlib_basic();
    let dir = tempfile::tempdir().unwrap();
    let summary = unpack(&f.data, &manifest_for(&f), dir.path()).unwrap();
    assert_eq!((summary.encoded, summary.preflated, summary.stored), (5, 0, 1));
    let kinds: Vec<_> = index(dir.path()).streams.iter().map(|s| method_kind(&s.method)).collect();
    assert_eq!(kinds, ["encode", "encode", "encode", "encode", "encode", "stored"]);

    // codecs: the hand-built lz4 frame of stored blocks matches no encoder and isn't
    // deflate, so it is kept verbatim.
    let f = zscan_fixtures::codecs();
    let dir = tempfile::tempdir().unwrap();
    let summary = unpack(&f.data, &manifest_for(&f), dir.path()).unwrap();
    assert_eq!((summary.preflated, summary.stored), (0, 1));
    let stored: Vec<_> = index(dir.path())
        .streams
        .iter()
        .filter(|s| matches!(s.method, Method::Stored { .. }))
        .map(|s| s.offset as usize)
        .collect();
    assert_eq!(stored, [f.expected[10].offset]);
}

#[test]
fn preflate_rebuilds_streams_from_another_compressor() {
    // miniz streams at every level: zlib reproduces none, preflate handles them all
    // with a small correction record.
    use zscan_fixtures::{Builder, Kind, records, text, zlib_miniz};
    let mut b = Builder::new(77);
    for level in [1, 3, 6, 9] {
        for kind_of_data in 0..2 {
            b.random(500);
            let p = if kind_of_data == 0 { text(&mut b.rng, 20_000) } else { records(&mut b.rng, 20_000) };
            b.foreign_stream(Kind::Zlib, zlib_miniz(&p, level), p);
        }
    }
    b.random(500);
    let f = b.finish("miniz", "");
    let dir = tempfile::tempdir().unwrap();
    let summary = unpack(&f.data, &manifest_for(&f), dir.path()).unwrap();
    assert_eq!((summary.encoded, summary.preflated, summary.stored), (0, 8, 0));
    let compressed: u64 = f.expected.iter().map(|e| e.compressed_size as u64).sum();
    assert!(summary.recon_bytes * 5 < compressed, "{} bytes of corrections for {compressed}", summary.recon_bytes);
    let mut out = Vec::new();
    rebuild(dir.path(), &mut out).unwrap();
    assert!(out == f.data);
}

#[test]
fn preflate_covers_streams_without_exact_params() {
    // With param matching off, every deflate-family stream has to go through preflate.
    let f = zscan_fixtures::gzip_basic();
    let opts = ScanOptions { match_params: false, ..Default::default() };
    let manifest = Manifest::new(SourceInfo::describe(Path::new("g"), &f.data), opts.clone(), scan(&f.data, &opts));
    let dir = tempfile::tempdir().unwrap();
    let summary = unpack(&f.data, &manifest, dir.path()).unwrap();
    assert_eq!((summary.encoded, summary.preflated, summary.stored), (0, f.expected.len(), 0));
    let mut out = Vec::new();
    rebuild(dir.path(), &mut out).unwrap();
    assert!(out == f.data);
}

#[test]
fn rebuild_refuses_changed_inputs() {
    let f = zscan_fixtures::zlib_basic();
    let fresh = || {
        let dir = tempfile::tempdir().unwrap();
        unpack(&f.data, &manifest_for(&f), dir.path()).unwrap();
        dir
    };

    // An edited contents file: rebuild restores originals only.
    let dir = fresh();
    let file = &index(dir.path()).streams[0].file;
    fs::write(dir.path().join("streams").join(file), b"edited").unwrap();
    let err = rebuild(dir.path(), &mut Vec::new()).unwrap_err();
    assert!(matches!(err, Error::Stream { ref reason, .. } if reason.contains("use pack")), "{err}");

    // Damaged bytes outside streams: caught by the whole-file CRC.
    let dir = fresh();
    let gaps = dir.path().join("gaps.bin");
    let mut bytes = fs::read(&gaps).unwrap();
    bytes[3] ^= 1;
    fs::write(&gaps, bytes).unwrap();
    assert!(matches!(rebuild(dir.path(), &mut Vec::new()), Err(Error::Verify { .. })));

    // Missing reconstruction data (stream 5 is kept verbatim in recon/).
    let dir = fresh();
    fs::remove_file(dir.path().join("recon").join("5.bin")).unwrap();
    assert!(matches!(rebuild(dir.path(), &mut Vec::new()), Err(Error::Io { .. })));

    // Truncated gaps.
    let dir = fresh();
    fs::write(dir.path().join("gaps.bin"), b"short").unwrap();
    assert!(matches!(rebuild(dir.path(), &mut Vec::new()), Err(Error::SourceMismatch(_))));
}

#[test]
fn unpack_needs_an_empty_directory_and_the_right_file() {
    let f = zscan_fixtures::gzip_basic();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("something"), b"x").unwrap();
    assert!(unpack(&f.data, &manifest_for(&f), dir.path()).is_err());

    let other = tempfile::tempdir().unwrap();
    let mut changed = f.data.clone();
    changed[0] ^= 1;
    assert!(matches!(unpack(&changed, &manifest_for(&f), other.path()), Err(Error::SourceMismatch(_))));
}
