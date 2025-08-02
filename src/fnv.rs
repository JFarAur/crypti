/// FNV‑1a 32‑bit prime
const FNV_PRIME: u32 = 16_777_619;

/// Hash a single byte, optionally folding ASCII upper‑case to lower‑case.
#[inline(always)]
fn fnv32_hash_single(value: u32, byte: u8, case_sensitive: bool) -> u32 {
    let b = if !case_sensitive && (b'A'..=b'Z').contains(&byte) {
        byte | 0x20
    } else {
        byte
    };
    (value ^ b as u32).wrapping_mul(FNV_PRIME)
}

/// Hash an ASCII/UTF‑8 string slice.
pub fn fnv32_hash_str(s: &str, seed: u32, case_sensitive: bool) -> u32 {
    s.as_bytes()
        .iter()
        .fold(seed, |acc, &b| fnv32_hash_single(acc, b, case_sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashfunc_fnv32() {
        let hash = fnv32_hash_str("MessageBoxW", 0x30ED04E4, true);
        assert!(hash == 0xC78B23C9);
    }
}
