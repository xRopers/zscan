//! Oodle (cargo feature `oodle`). zscan never includes the Oodle library, so the tests
//! that decode and encode need one: set ZSCAN_OODLE_DLL to your own oo2core library. They
//! pass without it, printing that they were skipped.
#![cfg(feature = "oodle")]

use std::collections::BTreeMap;
use std::path::Path;

use zscan_core::params::{OodleCompressor, OodleParams};
use zscan_core::plugins::OODLE_DLL_ENV;
use zscan_core::{
    Codec, DecodeError, Decoded, EncoderParams, ExtractOptions, Format, Manifest, Outcome, PackOptions, ScanOptions,
    SizeHint, SourceInfo, codec_for, decode_at, extract_all, pack, scan,
};
use zscan_fixtures::{Builder, Rng};

/// The Oodle codec, or `None` (and a note on stderr) when no library is configured.
fn oodle(test: &str) -> Option<&'static dyn Codec> {
    if std::env::var_os(OODLE_DLL_ENV).is_none() {
        eprintln!("{test}: skipped, set {OODLE_DLL_ENV} to an oo2core library to run it");
        return None;
    }
    Some(codec_for(Format::Oodle).expect("the library named by ZSCAN_OODLE_DLL should load"))
}

fn encode(codec: &dyn Codec, data: &[u8], compressor: OodleCompressor, level: i32) -> Vec<u8> {
    let none = Decoded { compressed_size: 0, body: 0..0, data: Vec::new(), original_name: None };
    codec.encode(&[], &none, data, &EncoderParams::Oodle(OodleParams { compressor, level })).unwrap()
}

fn with_oodle() -> ScanOptions {
    let mut opts = ScanOptions::default();
    opts.formats.push(Format::Oodle);
    opts
}

#[test]
fn without_a_library_the_error_says_what_to_do() {
    if std::env::var_os(OODLE_DLL_ENV).is_some() {
        return; // covered by the unit tests of the loader
    }
    let err = Format::Oodle.available().unwrap_err().to_string();
    assert!(err.contains("--oodle-dll") && err.contains(OODLE_DLL_ENV), "{err}");
    assert!(with_oodle().check_formats().is_err());
    let data = vec![0x8c, 0x06, 0, 0, 0];
    let err = decode_at(&data, 0, Format::Oodle, SizeHint::default(), 1 << 20, false).unwrap_err();
    assert!(matches!(err, DecodeError::Unavailable(_)), "{err:?}");
}

#[test]
fn the_walk_finds_the_end_of_every_stream() {
    let Some(codec) = oodle("the_walk_finds_the_end_of_every_stream") else { return };
    let mut rng = Rng::new(11);
    let text = zscan_fixtures::text(&mut rng, 700_000);
    let noise = rng.bytes(300_000);
    let compressors = [OodleCompressor::Kraken, OodleCompressor::Mermaid, OodleCompressor::Selkie, OodleCompressor::Leviathan];
    let expected_decoder = [0x06, 0x0a, 0x0a, 0x0c];
    for (&compressor, &decoder) in compressors.iter().zip(&expected_decoder) {
        for len in [1, 100, 0x3ffff, 0x40000, 0x40001, 700_000] {
            for (what, data) in [("text", &text[..len]), ("noise", &noise[..len.min(noise.len())])] {
                let stream = encode(codec, data, compressor, 4);
                let label = format!("{compressor:?} {what} {}", data.len());
                assert_eq!(stream[1] & 0x7f, decoder, "{label}: decoder type");
                let mut padded = stream.clone();
                padded.extend_from_slice(&[0x8c, 0x06, 0x12, 0x34, 0x56, 0x78]);
                let found = decode_at(&padded, 0, Format::Oodle, SizeHint { compressed: None, decompressed: Some(data.len()) }, 1 << 30, false)
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(found.compressed_size, stream.len() as u64, "{label}");
                assert_eq!(found.crc32, crc32fast::hash(data), "{label}");
            }
        }
    }
}

#[test]
fn needs_the_decompressed_size() {
    let Some(codec) = oodle("needs_the_decompressed_size") else { return };
    let text = zscan_fixtures::text(&mut Rng::new(2), 5000);
    let stream = encode(codec, &text, OodleCompressor::Kraken, 4);
    let err = decode_at(&stream, 0, Format::Oodle, SizeHint::default(), 1 << 20, false).unwrap_err();
    assert_eq!(err, DecodeError::SizeRequired("decompressed"));
    // Kraken blocks reject any other size (Leviathan's don't; see the codec's notes).
    for (size, compressed) in [(4999, None), (4000, Some(stream.len())), (5001, None), (5001, Some(stream.len()))] {
        let hint = SizeHint { compressed, decompressed: Some(size) };
        assert!(decode_at(&stream, 0, Format::Oodle, hint, 1 << 20, false).is_err(), "{hint:?}");
    }
    let right = SizeHint { compressed: Some(stream.len()), decompressed: Some(5000) };
    assert_eq!(decode_at(&stream, 0, Format::Oodle, right, 1 << 20, false).unwrap().decompressed_size, 5000);
}

/// Offset, contents and settings of each stream in [`archive`].
type Streams = Vec<(usize, Vec<u8>, OodleParams)>;

/// Oodle streams laid out like a game archive, each behind its size fields.
fn archive(codec: &dyn Codec) -> (Vec<u8>, Streams) {
    let mut b = Builder::new(12);
    let mut streams = Vec::new();
    b.random(900);
    let entries = [
        (b.text(40_000), OodleCompressor::Kraken, 4),
        (b.records(300_000), OodleCompressor::Mermaid, 6),
        (b.text(9000), OodleCompressor::Leviathan, 7),
        (b.records(20_000), OodleCompressor::Selkie, 2),
    ];
    for (i, (payload, compressor, level)) in entries.into_iter().enumerate() {
        let stream = encode(codec, &payload, compressor, level);
        if i % 2 == 0 {
            b.raw(&(payload.len() as u32).to_le_bytes());
            b.raw(&(stream.len() as u32).to_le_bytes());
        } else {
            b.raw(&(payload.len() as u64).to_le_bytes()); // a 64-bit size only
        }
        streams.push((b.data.len(), payload, OodleParams { compressor, level }));
        b.raw(&stream);
        b.random(500 + i * 77);
    }
    (b.data, streams)
}

#[test]
fn scanning_is_opt_in_and_finds_streams_behind_size_fields() {
    let Some(codec) = oodle("scanning_is_opt_in_and_finds_streams_behind_size_fields") else { return };
    let (data, streams) = archive(codec);
    assert!(scan(&data, &ScanOptions::default()).is_empty());
    let found = scan(&data, &with_oodle());
    let got: Vec<_> = found.iter().map(|s| (s.offset as usize, s.decompressed_size as usize, s.crc32)).collect();
    let want: Vec<_> = streams.iter().map(|(o, p, _)| (*o, p.len(), crc32fast::hash(p))).collect();
    assert_eq!(got, want);
    for (s, (_, _, params)) in found.iter().zip(&streams) {
        let Some(EncoderParams::Oodle(p)) = &s.exact_params else { panic!("no exact params for {params:?}") };
        // Kraken-family compressors can share a decoder (Mermaid and Selkie both use
        // Mermaid's); any setting that reproduces the stream is fine.
        assert!(p.compressor == params.compressor || p.compressor == OodleCompressor::Mermaid, "{p:?} for {params:?}");
    }
}

#[test]
fn no_false_positives_in_the_other_fixtures() {
    if oodle("no_false_positives_in_the_other_fixtures").is_none() {
        return;
    }
    for f in zscan_fixtures::all() {
        let hits: Vec<_> = scan(&f.data, &with_oodle()).into_iter().filter(|s| s.format == Format::Oodle).collect();
        assert!(hits.is_empty(), "fixture {}: {hits:?}", f.name);
    }
}

#[test]
fn extract_edit_pack_round_trip() {
    let Some(codec) = oodle("extract_edit_pack_round_trip") else { return };
    let (data, streams) = archive(codec);
    let opts = with_oodle();
    let manifest = Manifest::new(SourceInfo::describe(Path::new("oodle.bin"), &data), opts.clone(), scan(&data, &opts));
    assert_eq!(manifest.streams.len(), streams.len());
    // The manifest records the sizes, which is all extract needs to decode Oodle again.
    let reloaded = Manifest::from_json(&manifest.to_json()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = extract_all(&data, &reloaded, dir.path(), &ExtractOptions::default()).unwrap();
    for (file, (_, payload, _)) in files.iter().zip(&streams) {
        assert!(std::fs::read(&file.path).unwrap() == *payload);
    }

    let mut edited = streams[1].1[..200_000].to_vec();
    edited[5..11].copy_from_slice(b"EDITED");
    let edits = BTreeMap::from([(reloaded.streams[1].id, edited.clone())]);
    let result = pack(&data, &reloaded, &edits, &PackOptions::default()).unwrap();
    assert!(result.fits());
    let Outcome::Repacked { reused_original_params, .. } = &result.streams[1].outcome else { panic!("not repacked") };
    assert!(reused_original_params);
    let out = result.apply(&data).unwrap();
    let packed = result.verify_output(&out).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for file in extract_all(&out, &packed, dir.path(), &ExtractOptions::default()).unwrap() {
        let want = if file.id == reloaded.streams[1].id { &edited } else { &streams[file.id as usize].1 };
        assert!(std::fs::read(&file.path).unwrap() == *want, "stream {}", file.id);
    }
}
