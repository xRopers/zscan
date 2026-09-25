//! The optional codecs from the command line: LZO and Oodle, in builds with and without
//! their cargo features.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

/// Run zscan with no Oodle library configured.
fn zscan(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zscan")).args(args).env_remove("ZSCAN_OODLE_DLL").output().expect("failed to run zscan")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[cfg_attr(not(feature = "lzo"), allow(dead_code))]
fn ok_json(args: &[&str]) -> Value {
    let out = zscan(args);
    assert!(out.status.success(), "zscan {args:?} failed: {}", stderr(&out));
    serde_json::from_slice(&out.stdout).expect("stdout is not JSON")
}

fn write(dir: &Path, name: &str, data: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn missing_support_is_explained() {
    let tmp = tempfile::tempdir().unwrap();
    let input = write(tmp.path(), "in.bin", &zscan_fixtures::zlib_basic().data);

    let out = zscan(&["scan", &input, "--scan-oodle"]);
    assert!(!out.status.success());
    let want = if cfg!(feature = "oodle") { "--oodle-dll" } else { "--features oodle" };
    assert!(stderr(&out).contains(want), "{}", stderr(&out));

    if cfg!(feature = "oodle") {
        let out = zscan(&["--oodle-dll", "no/such/oo2core_9_win64.dll", "scan", &input, "--scan-oodle"]);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("not found"), "{}", stderr(&out));
    }

    if !cfg!(feature = "lzo") {
        for args in [vec!["scan", &input, "--formats", "lzo"], vec!["try", &input, "--at", "0", "--format", "lzo"]] {
            let out = zscan(&args);
            assert!(!out.status.success());
            assert!(stderr(&out).contains("--features lzo"), "{args:?}: {}", stderr(&out));
        }
    }
}

#[cfg(feature = "lzo")]
#[test]
fn lzo_scan_then_try_with_size_fields_extract_and_pack() {
    let tmp = tempfile::tempdir().unwrap();
    let f = zscan_fixtures::lzo_streams();
    let input = write(tmp.path(), "lzo.bin", &f.data);

    // Scanning finds them only when asked.
    assert_eq!(ok_json(&["scan", &input, "--json"])["streams"].as_array().unwrap().len(), 0);
    let scanned = ok_json(&["scan", &input, "--formats", "lzo", "--json"]);
    let offsets: Vec<u64> = scanned["streams"].as_array().unwrap().iter().map(|s| s["offset"].as_u64().unwrap()).collect();
    assert_eq!(offsets, f.expected.iter().map(|e| e.offset as u64).collect::<Vec<_>>());

    // By hand: an empty manifest, then one stream with its size fields.
    let manifest = tmp.path().join("m.json");
    let manifest = manifest.to_str().unwrap();
    ok_json(&["scan", &input, "-o", manifest, "--json"]);
    let e = &f.expected[1];
    let (at, dsize, csize) = (format!("{:#x}", e.offset), format!("@{:#x}", e.offset - 8), format!("@{:#x}:u32le", e.offset - 4));
    let tried = ok_json(&["try", &input, "--at", &at, "--format", "lzo", "--decompressed-size", &dsize, "--compressed-size", &csize, "-m", manifest, "--json"]);
    assert_eq!(tried["decompressed_size"], e.payload.len() as u64);
    assert_eq!(tried["added_as"], 0);
    let m: Value = serde_json::from_str(&std::fs::read_to_string(manifest).unwrap()).unwrap();
    assert_eq!(m["streams"][0]["length_fields"].as_array().unwrap().len(), 2);
    assert_eq!(m["streams"][0]["exact_params"]["encoder"], "lzo");

    // Wrong sizes are refused.
    let out = zscan(&["try", &input, "--at", &at, "--format", "lzo", "--decompressed-size", "5"]);
    assert!(!out.status.success());

    // Extract, shrink the stream, pack: the size fields follow.
    let dir = tmp.path().join("out");
    let dir = dir.to_str().unwrap();
    let files = ok_json(&["extract", &input, "-m", manifest, "-d", dir, "--json"]);
    let file = files[0]["path"].as_str().unwrap();
    assert!(std::fs::read(file).unwrap() == e.payload);
    std::fs::write(file, &e.payload[..6000]).unwrap();
    let packed = tmp.path().join("packed.bin");
    let report = ok_json(&["pack", &input, "-m", manifest, "-d", dir, "-o", packed.to_str().unwrap(), "--json"]);
    assert_eq!(report["field_updates"].as_array().unwrap().len(), 2);
    let out = std::fs::read(&packed).unwrap();
    let read = |o: usize| u32::from_le_bytes(out[o..o + 4].try_into().unwrap());
    assert_eq!(read(e.offset - 8), 6000);
    assert!(read(e.offset - 4) < e.compressed_size as u32);
}
