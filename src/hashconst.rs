use crate::registers::Value;

pub fn known_hash_u32(hash_value: u32) -> Option<String> {
    match hash_value {
        0x4F727068
        | 0x65616E42
        | 0x65686F6C
        | 0x64657253
        | 0x63727944
        | 0x6F756274 => Some("BCRYPT".to_string()),
        0x67452301
        | 0xefcdab89
        | 0x98badcfe
        | 0x10325476 => Some("MD4/MD5/SHA1".to_string()),
        0xc3d2e1f0
        | 0x5a827999
        | 0x6ed9eba1
        | 0x8f1bbcdc
        | 0xca62c1d6 => Some("SHA1".to_string()),
        0xc1059ed8
        | 0x367cd507
        | 0x3070dd17
        | 0xf70e5939
        | 0xffc00b31
        | 0x68581511
        | 0x64f98fa7
        | 0xbefa4fa4 => Some("SHA224".to_string()),
        0x6a09e667
        | 0xbb67ae85
        | 0x3c6ef372
        | 0xa54ff53a
        | 0x510e527f
        | 0x9b05688c
        | 0x1f83d9ab
        | 0x5be0cd19 => Some("SHA256".to_string()),
        0x811c9dc5
        | 0x1000193 => Some("FNV/32".to_string()),
        _ => None
    }
}

pub fn known_factor_u32(factor: u32) -> Option<String> {
    match factor {
        0x1000193 => Some("FNV/32".to_string()),
        _ => None
    }
}

pub fn known_hash_u64(hash_value: u64) -> Option<String> {
    match hash_value {
        0x736f6d6570736575
        | 0x646f72616e646f6d
        | 0x6c7967656e657261
        | 0x7465646279746573 => Some("SIPHASH".to_string()),
        0xcbbb9d5dc1059ed8
        | 0x629a292a367cd507
        | 0x9159015a3070dd17
        | 0x152fecd8f70e5939
        | 0x67332667ffc00b31
        | 0x8eb44a8768581511
        | 0xdb0c2e0d64f98fa7
        | 0x47b5481dbefa4fa4 => Some("SHA384".to_string()),
        0x6a09e667f3bcc908
        | 0xbb67ae8584caa73b
        | 0x3c6ef372fe94f82b
        | 0xa54ff53a5f1d36f1
        | 0x510e527fade682d1
        | 0x9b05688c2b3e6c1f
        | 0x1f83d9abfb41bd6b
        | 0x5be0cd19137e2179 => Some("SHA512".to_string()),
        0xcbf29ce484222325
        | 0x100000001b3 => Some("FNV/64".to_string()),
        _ => None
    }
}

pub fn known_factor_u64(factor: u64) -> Option<String> {
    match factor {
        0x100000001b3 => Some("FNV/64".to_string()),
        _ => None
    }
}

pub fn is_known_hash_func(hash_value: &Value, size: usize) -> Option<String> {
    let as_u32 = {
        if size >= 4 { known_hash_u32(hash_value.as_zex_u32(4)) } else { None }
    };

    let as_u64 = {
        if size >= 8 { known_hash_u64(hash_value.as_zex_u64(8)) } else { None }
    };

    return as_u32.or(as_u64);
}