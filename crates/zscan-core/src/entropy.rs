//! Shannon entropy, for the `info` map and the optional output-entropy filter.

use serde::Serialize;

/// Entropy of `data` in bits per byte (0.0 ..= 8.0).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[usize::from(b)] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyBlock {
    pub offset: u64,
    pub len: u64,
    pub entropy: f64,
}

/// Split `data` into about `blocks` equal blocks and measure each one.
pub fn entropy_map(data: &[u8], blocks: usize) -> Vec<EntropyBlock> {
    if data.is_empty() || blocks == 0 {
        return Vec::new();
    }
    let block_len = data.len().div_ceil(blocks);
    data.chunks(block_len)
        .enumerate()
        .map(|(i, chunk)| EntropyBlock {
            offset: (i * block_len) as u64,
            len: chunk.len() as u64,
            entropy: shannon(chunk),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extremes() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[7; 100]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn map_covers_input() {
        let data = vec![0u8; 1000];
        let map = entropy_map(&data, 7);
        assert_eq!(map.iter().map(|b| b.len).sum::<u64>(), 1000);
        assert!(map.len() <= 7);
    }
}
