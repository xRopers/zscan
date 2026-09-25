//! End-to-end tests of the `zscan` binary.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn zscan(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zscan")).args(args).output().expect("failed to run zscan")
}

fn ok_json(args: &[&str]) -> Value {
    let out = zscan(args);
    assert!(out.status.success(), "zscan {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).expect("stdout is not JSON")
}

fn write_fixture(dir: &Path, f: &zscan_fixtures::Fixture) -> String {
    let path = dir.join(format!("{}.bin", f.name));
    std::fs::write(&path, &f.data).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn scan_then_extract_with_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let f = zscan_fixtures::mixed();
    let input = write_fixture(tmp.path(), &f);
    let manifest = tmp.path().join("m.json");
    let manifest = manifest.to_str().unwrap();

    let scanned = ok_json(&["scan", &input, "-o", manifest, "--json"]);
    let streams = scanned["streams"].as_array().unwrap();
    assert_eq!(streams.len(), f.expected.len());
    for (s, e) in streams.iter().zip(&f.expected) {
        assert_eq!(s["offset"], e.offset as u64);
        assert_eq!(s["format"], e.kind.as_str());
    }
    assert!(Path::new(manifest).exists());

    let out_dir = tmp.path().join("out");
    let extracted = ok_json(&["extract", &input, "-m", manifest, "-d", out_dir.to_str().unwrap(), "--json"]);
    let extracted = extracted.as_array().unwrap();
    assert_eq!(extracted.len(), f.expected.len());
    for (x, e) in extracted.iter().zip(&f.expected) {
        assert_eq!(std::fs::read(x["path"].as_str().unwrap()).unwrap(), e.payload);
    }
}

#[test]
fn extract_without_manifest_scans_first() {
    let tmp = tempfile::tempdir().unwrap();
    let f = zscan_fixtures::gzip_basic();
    let input = write_fixture(tmp.path(), &f);
    let out_dir = tmp.path().join("out");
    let out = zscan(&["extract", &input, "-d", out_dir.to_str().unwrap()]);
    assert!(out.status.success());
    assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), f.expected.len());
}

#[test]
fn extract_refuses_mismatched_input_unless_forced() {
    let tmp = tempfile::tempdir().unwrap();
    let f = zscan_fixtures::zlib_basic();
    let input = write_fixture(tmp.path(), &f);
    let manifest = tmp.path().join("m.json");
    let manifest = manifest.to_str().unwrap();
    assert!(zscan(&["scan", &input, "-o", manifest]).status.success());

    // Change a filler byte (outside every stream).
    let mut data = f.data.clone();
    data[0] ^= 1;
    std::fs::write(&input, &data).unwrap();

    let out_dir = tmp.path().join("out");
    let out_dir = out_dir.to_str().unwrap();
    let out = zscan(&["extract", &input, "-m", manifest, "-d", out_dir]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not match the manifest"));

    assert!(zscan(&["extract", &input, "-m", manifest, "-d", out_dir, "--force"]).status.success());
}

#[test]
fn scan_refuses_to_overwrite_input() {
    let tmp = tempfile::tempdir().unwrap();
    let f = zscan_fixtures::zlib_basic();
    let input = write_fixture(tmp.path(), &f);
    let out = zscan(&["scan", &input, "-o", &input]);
    assert!(!out.status.success());
    assert_eq!(std::fs::read(&input).unwrap(), f.data);
}

#[test]
fn info_reports_streams_and_entropy() {
    let tmp = tempfile::tempdir().unwrap();
    let f = zscan_fixtures::deflate_raw();
    let input = write_fixture(tmp.path(), &f);
    let info = ok_json(&["info", &input, "--blocks", "32", "--json"]);
    assert_eq!(info["size"], f.data.len() as u64);
    assert_eq!(info["stream_count"], f.expected.len() as u64);
    assert!(info["entropy_map"].as_array().unwrap().len() <= 32);

    let text = zscan(&["info", &input]);
    assert!(text.status.success());
    assert!(String::from_utf8_lossy(&text.stdout).contains("entropy map"));
}

#[test]
fn format_flag_parses() {
    let tmp = tempfile::tempdir().unwrap();
    let f = zscan_fixtures::mixed();
    let input = write_fixture(tmp.path(), &f);
    let scanned = ok_json(&["scan", &input, "--formats", "gzip,zlib", "--json"]);
    assert_eq!(scanned["streams"].as_array().unwrap().len(), 2);
    assert!(!zscan(&["scan", &input, "--formats", "lzma"]).status.success());
}
