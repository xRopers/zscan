//! Compares a scan manifest with a generator's expected list:
//! `check-scan <manifest.json> <expected.json>`. Exits non-zero on any difference.
//!
//! Streams match on offset, format, compressed size and CRC-32.

use std::collections::BTreeSet;

use serde_json::Value;

type Key = (u64, String, u64, String);

fn keys(doc: &Value) -> BTreeSet<Key> {
    doc["streams"]
        .as_array()
        .expect("`streams` array")
        .iter()
        .map(|s| {
            (
                s["offset"].as_u64().unwrap(),
                s["format"].as_str().unwrap().to_string(),
                s["compressed_size"].as_u64().unwrap(),
                s["crc32"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: check-scan <manifest.json> <expected.json>");
        std::process::exit(2);
    }
    let read = |p: &str| -> Value { serde_json::from_str(&std::fs::read_to_string(p).expect(p)).expect(p) };
    let manifest = read(&args[1]);
    let (found, expected) = (keys(&manifest), keys(&read(&args[2])));
    let exact = manifest["streams"].as_array().unwrap().iter().filter(|s| s["params"]["exact_match"] == true).count();
    let missing: Vec<_> = expected.difference(&found).collect();
    let extra: Vec<_> = found.difference(&expected).collect();
    println!(
        "expected {}, found {}, missing {}, extra {}, exact params {exact}",
        expected.len(),
        found.len(),
        missing.len(),
        extra.len()
    );
    for m in missing.iter().take(10) {
        println!("  missing {m:?}");
    }
    for e in extra.iter().take(10) {
        println!("  extra   {e:?}");
    }
    if !missing.is_empty() || !extra.is_empty() {
        std::process::exit(1);
    }
}
