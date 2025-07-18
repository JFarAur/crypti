use crate::data_winapi::FNS_ALL;

/// Given an arbitrary hash function on a numeric type, brute force a Windows API hash.
pub fn find_api_hash_seeded<T: PartialEq + Copy + Clone>(seed: T, hash: T, hash_func: fn (&str, T, bool) -> T) -> Option<&'static str> {
    for &export_collection in FNS_ALL {
        for &export in export_collection {
            if hash_func(export, seed, true) == hash {
                return Some(export);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fnv::fnv32_hash_str;

    #[test]
    fn test_hash_find() {
        let api = find_api_hash_seeded(0x30ED04E4, 0xC78B23C9, fnv32_hash_str).unwrap();
        assert!(api.eq("MessageBoxW"));
    }
}