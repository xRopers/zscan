//! Pack: reinjecting edited streams, fitting, and verification.

use std::collections::BTreeMap;
use std::path::Path;

use zscan_core::{
    EncoderParams, Error, ExtractOptions, Manifest, Outcome, PackOptions, PackResult, ScanOptions, SourceInfo, extract_all, load_edits,
    pack, scan,
};
use zscan_fixtures::{Builder, Fixture, Kind};

fn manifest_for(data: &[u8]) -> Manifest {
    let opts = ScanOptions::default();
    let found = scan(data, &opts);
    Manifest::new(SourceInfo::describe(Path::new("input.bin"), data), opts, found)
}

fn pack_ok(data: &[u8], manifest: &Manifest, edits: &BTreeMap<u32, Vec<u8>>) -> (PackResult, Vec<u8>) {
    let result = pack(data, manifest, edits, &PackOptions::default()).unwrap();
    let out = result.apply(data).expect("pack should fit");
    (result, out)
}

/// A shorter, slightly different version of `payload`, which should always fit.
fn shrink(payload: &[u8]) -> Vec<u8> {
    let mut edit = payload[..payload.len() * 3 / 4].to_vec();
    edit[0] ^= 0x20;
    edit
}

fn fixtures_with_streams() -> Vec<Fixture> {
    zscan_fixtures::all().into_iter().filter(|f| !f.expected.is_empty()).collect()
}

#[test]
fn no_edits_reproduces_the_input() {
    for f in zscan_fixtures::all() {
        let manifest = manifest_for(&f.data);
        let (result, out) = pack_ok(&f.data, &manifest, &BTreeMap::new());
        assert!(out == f.data, "fixture {}", f.name);
        assert!(result.streams.iter().all(|s| s.outcome == Outcome::Unchanged));
    }
}

#[test]
fn every_stream_edited_round_trips() {
    for f in fixtures_with_streams() {
        let manifest = manifest_for(&f.data);
        let edits: BTreeMap<u32, Vec<u8>> =
            manifest.streams.iter().zip(&f.expected).map(|(s, e)| (s.id, shrink(&e.payload))).collect();
        let (result, out) = pack_ok(&f.data, &manifest, &edits);
        assert_eq!(result.repacked().count(), f.expected.len(), "fixture {}", f.name);
        assert_eq!(out.len(), f.data.len());

        // Bytes outside the stream slots are untouched; freed slot space is zeroed.
        let mut pos = 0;
        for plan in &result.streams {
            let (start, new_end, old_end) = (
                plan.offset as usize,
                (plan.offset + plan.new_size()) as usize,
                (plan.offset + plan.original_size) as usize,
            );
            assert!(out[pos..start] == f.data[pos..start], "fixture {}: bytes before {start:#x} changed", f.name);
            assert!(out[new_end..old_end].iter().all(|&b| b == 0), "fixture {}: padding not zeroed", f.name);
            pos = old_end;
        }
        assert!(out[pos..] == f.data[pos..]);

        // The returned manifest describes the packed file: extracting gives the edits back.
        let packed_manifest = result.verify_output(&out).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let files = extract_all(&out, &packed_manifest, dir.path(), &ExtractOptions::default()).unwrap();
        for file in files {
            assert_eq!(std::fs::read(&file.path).unwrap(), edits[&file.id], "fixture {} stream {}", f.name, file.id);
        }
    }
}

#[test]
fn matched_params_are_reused_and_recorded() {
    let f = zscan_fixtures::zlib_basic();
    let manifest = manifest_for(&f.data);
    let edits = BTreeMap::from([(0, shrink(&f.expected[0].payload)), (5, shrink(&f.expected[5].payload))]);
    let (result, out) = pack_ok(&f.data, &manifest, &edits);

    let Outcome::Repacked { params, reused_original_params, .. } = &result.streams[0].outcome else { panic!() };
    assert!(reused_original_params);
    assert_eq!(Some(params), manifest.streams[0].exact_params.as_ref());

    // Stream 5 was made by miniz, so there were no exact params to reuse.
    let Outcome::Repacked { reused_original_params, .. } = result.streams[5].outcome else { panic!() };
    assert!(!reused_original_params);

    // Rescanning the packed file finds the new streams and matches their params exactly.
    let rescanned = scan(&out, &ScanOptions::default());
    assert_eq!(rescanned.len(), manifest.streams.len());
    assert!(rescanned.iter().all(|s| s.exact_params.is_some()));
}

#[test]
fn gzip_header_is_kept() {
    let f = zscan_fixtures::gzip_basic();
    let manifest = manifest_for(&f.data);
    let edits = BTreeMap::from([(0, b"replacement text for hello.txt, long enough to pass min-size".to_vec())]);
    let (_, out) = pack_ok(&f.data, &manifest, &edits);
    let rescanned = scan(&out, &ScanOptions::default());
    assert_eq!(rescanned[0].original_name.as_deref(), Some("hello.txt"));
    assert_eq!(rescanned[0].decompressed_size, edits[&0].len() as u64);
    // The 10-byte fixed header plus "hello.txt\0" is byte-identical.
    let start = f.expected[0].offset;
    assert_eq!(out[start..start + 20], f.data[start..start + 20]);
}

#[test]
fn zlib_window_never_exceeds_header() {
    let f = zscan_fixtures::zlib_basic();
    let manifest = manifest_for(&f.data);
    let small_window = 4; // the stream whose header declares a 4 KiB window
    let window = |p: &EncoderParams| p.as_deflate().unwrap().window_bits;
    assert_eq!(window(manifest.streams[small_window].exact_params.as_ref().unwrap()), 12);
    let edits = BTreeMap::from([(small_window as u32, shrink(&f.expected[small_window].payload))]);
    let (result, _) = pack_ok(&f.data, &manifest, &edits);
    let Outcome::Repacked { params, .. } = &result.streams[small_window].outcome else { panic!() };
    assert_eq!(window(params), 12);

    // Even hand-edited params can't raise the window past what the header declares.
    let mut widened = manifest.clone();
    if let Some(EncoderParams::Deflate(p)) = &mut widened.streams[small_window].exact_params {
        p.window_bits = 15;
    }
    let result = pack(&f.data, &widened, &edits, &PackOptions::default()).unwrap();
    let Outcome::Repacked { params, .. } = &result.streams[small_window].outcome else { panic!() };
    assert_eq!(window(params), 12);
}

#[test]
fn too_large_is_reported_with_the_overflow() {
    let f = zscan_fixtures::zlib_basic();
    let manifest = manifest_for(&f.data);
    let mut rng = zscan_fixtures::Rng::new(5);
    let edits = BTreeMap::from([(1, shrink(&f.expected[1].payload)), (2, rng.bytes(20_000))]);
    let result = pack(&f.data, &manifest, &edits, &PackOptions::default()).unwrap();
    assert!(!result.fits() && result.apply(&f.data).is_none());
    let failures: Vec<_> = result.failures().collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].id, 2);
    let Outcome::TooLarge { best_size, available } = failures[0].outcome else { panic!() };
    assert_eq!(available, manifest.streams[2].compressed_size);
    assert!(best_size > 20_000);
    // The stream that did fit is still reported, for dry-run output.
    assert!(matches!(result.streams[1].outcome, Outcome::Repacked { .. }));
}

#[test]
fn zero_slack_is_opt_in() {
    let mut b = Builder::new(11);
    b.random(100);
    let p = b.text(2000);
    b.stream(Kind::Zlib, zscan_fixtures::zlib(&p, 6), p.clone(), None);
    b.zeros(600);
    b.random(100);
    let f = b.finish("slack", "");
    let manifest = manifest_for(&f.data);

    let mut bigger = p;
    bigger.extend(zscan_fixtures::text(&mut zscan_fixtures::Rng::new(12), 1000));
    let edits = BTreeMap::from([(0, bigger)]);

    let strict = pack(&f.data, &manifest, &edits, &PackOptions::default()).unwrap();
    assert_eq!(strict.failures().count(), 1);

    let opts = PackOptions { use_zero_slack: true, ..Default::default() };
    let result = pack(&f.data, &manifest, &edits, &opts).unwrap();
    let out = result.apply(&f.data).unwrap();
    let Outcome::Repacked { slack_used, new_size, .. } = result.streams[0].outcome else { panic!() };
    assert!(slack_used > 0 && slack_used <= 600);
    assert_eq!(new_size, manifest.streams[0].compressed_size + slack_used);
    let end = f.data.len() - 100;
    assert_eq!(out[end..], f.data[end..], "bytes after the zero run are untouched");
}

#[test]
fn rejects_bad_input() {
    let f = zscan_fixtures::zlib_basic();
    let manifest = manifest_for(&f.data);
    let opts = PackOptions::default();

    let unknown = BTreeMap::from([(99, vec![1, 2, 3])]);
    assert!(matches!(pack(&f.data, &manifest, &unknown, &opts), Err(Error::InvalidManifest(_))));

    let mut overlapping = manifest.clone();
    overlapping.streams[1].offset = overlapping.streams[0].offset + 1;
    let r = pack(&f.data, &overlapping, &BTreeMap::new(), &PackOptions { verify_source: false, ..opts.clone() });
    assert!(matches!(r, Err(Error::InvalidManifest(_))));

    let mut changed = f.data.clone();
    changed[0] ^= 1;
    assert!(matches!(pack(&changed, &manifest, &BTreeMap::new(), &opts), Err(Error::SourceMismatch(_))));

    let mut bad_params = manifest.clone();
    let Some(EncoderParams::Deflate(p)) = &mut bad_params.streams[0].exact_params else { panic!() };
    p.mem_level = 12;
    let edits = BTreeMap::from([(0, shrink(&f.expected[0].payload))]);
    assert!(matches!(pack(&f.data, &bad_params, &edits, &opts), Err(Error::InvalidManifest(_))));
}

#[test]
fn load_edits_picks_up_only_changed_files() {
    let f = zscan_fixtures::mixed();
    let manifest = manifest_for(&f.data);
    let dir = tempfile::tempdir().unwrap();
    let files = extract_all(&f.data, &manifest, dir.path(), &ExtractOptions::default()).unwrap();
    assert!(load_edits(dir.path(), &manifest).unwrap().is_empty());

    std::fs::write(&files[1].path, b"edited").unwrap();
    std::fs::remove_file(&files[2].path).unwrap();
    let edits = load_edits(dir.path(), &manifest).unwrap();
    assert_eq!(edits.keys().copied().collect::<Vec<_>>(), [files[1].id]);
    assert_eq!(edits[&files[1].id], b"edited");
}

#[test]
fn packing_twice_is_stable() {
    let f = zscan_fixtures::mixed();
    let manifest = manifest_for(&f.data);
    let edits = BTreeMap::from([(0, shrink(&f.expected[0].payload))]);
    let (first, out) = pack_ok(&f.data, &manifest, &edits);
    let packed_manifest = first.verify_output(&out).unwrap();
    // Packing the same edit into the packed file changes nothing.
    let (_, again) = pack_ok(&out, &packed_manifest, &edits);
    assert!(again == out);
}

#[test]
fn streamed_output_matches_apply_and_verify_catches_damage() {
    let f = zscan_fixtures::gzip_basic();
    let manifest = manifest_for(&f.data);
    let edits = BTreeMap::from([(1, shrink(&f.expected[1].payload))]);
    let (result, out) = pack_ok(&f.data, &manifest, &edits);

    let mut streamed = Vec::new();
    result.write_to(&f.data, &mut streamed).unwrap();
    assert!(streamed == out);

    let packed_manifest = result.verify_output(&out).unwrap();
    assert_eq!(packed_manifest.source.size, out.len() as u64);
    packed_manifest.source.check(&out).unwrap();

    // Damage an unchanged stream and the edited one in turn: both are caught.
    for id in [0usize, 1] {
        let mut damaged = out.clone();
        damaged[packed_manifest.streams[id].offset as usize + 20] ^= 0x40;
        let err = result.verify_output(&damaged).unwrap_err();
        assert!(matches!(err, Error::Verify { id: bad, .. } if bad as usize == id), "{err}");
    }
}

#[test]
fn repacked_streams_of_every_format_are_reproducible() {
    // Edit every stream of the multi-codec fixture; a rescan of the packed file must find
    // each new stream and match the settings pack used, byte for byte.
    let f = zscan_fixtures::codecs();
    let manifest = manifest_for(&f.data);
    let edits: BTreeMap<u32, Vec<u8>> =
        manifest.streams.iter().zip(&f.expected).map(|(s, e)| (s.id, shrink(&e.payload))).collect();
    let (result, out) = pack_ok(&f.data, &manifest, &edits);
    let rescanned = scan(&out, &ScanOptions::default());
    assert_eq!(rescanned.len(), manifest.streams.len());
    let mut ctx = zscan_core::DecodeCtx::new(1 << 24);
    for (plan, found) in result.streams.iter().zip(&rescanned) {
        assert!(matches!(plan.outcome, Outcome::Repacked { .. }), "stream {} not repacked", plan.id);
        assert_eq!(found.offset, plan.offset);
        // Several settings can give identical output (for small inputs, zstd levels
        // 16-19 do), so the rescan may name different ones; they must still rebuild it.
        let what = format!("{} stream {}", plan.format, plan.id);
        let params = found.exact_params.as_ref().unwrap_or_else(|| panic!("{what}: no exact params"));
        let stream = &out[found.offset as usize..found.end() as usize];
        let codec = zscan_core::codec_for(found.format);
        let decoded = codec.decode(stream, &mut ctx).unwrap();
        assert!(codec.encode(stream, &decoded, &edits[&plan.id], params) == stream, "{what}");
    }
}

#[test]
fn brotli_round_trip() {
    // Brotli is never scanned for: build the manifest from streams at known offsets.
    let f = zscan_fixtures::brotli_streams();
    let mut manifest = Manifest::new(SourceInfo::describe(Path::new("b.bin"), &f.data), ScanOptions::default(), vec![]);
    for e in &f.expected {
        let found = zscan_core::decode_at(&f.data, e.offset as u64, zscan_core::Format::Brotli, 1 << 30, true).unwrap();
        manifest.add_stream(found).unwrap();
    }
    let edits = BTreeMap::from([(0, shrink(&f.expected[0].payload))]);
    let (result, out) = pack_ok(&f.data, &manifest, &edits);
    let packed_manifest = result.verify_output(&out).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = extract_all(&out, &packed_manifest, dir.path(), &ExtractOptions::default()).unwrap();
    assert_eq!(std::fs::read(&files[0].path).unwrap(), edits[&0]);
}
