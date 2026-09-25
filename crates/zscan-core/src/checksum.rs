//! Checksums used by the stream formats.

/// CRC-32 (IEEE), as used by gzip and by the manifest.
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Adler-32 (RFC 1950), as used by zlib.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    // Largest n such that 255n(n+1)/2 + (n+1)(MOD-1) fits in a u32.
    const NMAX: usize = 5552;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(NMAX) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        // Long input exercises the NMAX chunking.
        let long = vec![0xffu8; 100_000];
        let (mut a, mut b) = (1u64, 0u64);
        for &x in &long {
            a = (a + u64::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(adler32(&long), ((b << 16) | a) as u32);
    }

    #[test]
    fn crc32_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
