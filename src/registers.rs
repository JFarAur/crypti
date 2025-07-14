use std::collections::{HashMap};
use bytemuck::{from_bytes, from_bytes_mut, AnyBitPattern, NoUninit};

#[derive(Clone, Copy)]
pub struct Value {
    pub data: [u8; 64],
}

impl Value {
    /// View the first `size_of::<T>()` bytes of the buffer as a `&T`.
    #[allow(dead_code)]
    pub fn as_ref<T>(&self) -> &T
    where
        T: AnyBitPattern,
    {
        let len = core::mem::size_of::<T>();
        assert!(
            len <= self.data.len(),
            "type {:?} ({} bytes) does not fit into 64-byte buffer",
            core::any::type_name::<T>(),
            len,
        );

        from_bytes(&self.data[..len])
    }

    /// View the first `size_of::<T>()` bytes of the buffer as a mutable `&T`.
    #[allow(dead_code)]
    pub fn as_mut<T>(&mut self) -> &mut T
    where
        T: AnyBitPattern,
        T: NoUninit,
    {
        let len = core::mem::size_of::<T>();
        assert!(len <= self.data.len());
        from_bytes_mut(&mut self.data[..len])
    }

    /// Get this value reinterpreted as a value of `size` bytes, but zero-extended to a u64.
    /// `size` must be 8 or fewer bytes.
    pub fn as_zex_u64(&self, size: usize) -> u64
    {
        assert!(
            size <= 8,
            "type ({} bytes) does not fit into 8-byte buffer",
            size,
        );

        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(&self.data[..size]);
        *from_bytes(&buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Value {
        let mut data = [0u8; 64];
        data[..bytes.len()].copy_from_slice(bytes);
        Value{ data: data }
    }

    pub fn zero() -> Value {
        Value{ data: [0; 64] }
    }

    pub fn map_bytewise_masked<F: Fn(u8, u8) -> u8>(&self, val2: &Value, mask: u64, f: F) -> Value {
        let data = self.data
            .iter()
            .zip(val2.data.iter())
            .enumerate()
            .map(|(pos, (a, b))| match mask & (1 << pos) { 0 => *a, _ => f(*a, *b) } )
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        Value {
            data: data
        }
    }
}

pub fn get_reg_val(regmap: &HashMap<String, Value>,
                    reg: &str) -> Option<Value> {
    regmap.get(reg).copied()
}

pub fn set_reg_val(regmap: &mut HashMap<String, Value>,
                    reg: &str,
                    val: &Value,
                    size: usize) {
    let exis: &mut Value = regmap.entry(reg.to_string()).or_insert(Value{ data: [0; 64] });
    exis.data[0..size].copy_from_slice(&val.data[0..size]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_bytewise_one_byte() {
        let val1 = Value::from_bytes(&[0xE4]);
        let val2 = Value::from_bytes(&[0x34]);

        let result = val1.map_bytewise_masked(&val2, !0, |a, b| a ^ b);
        let expected = Value::from_bytes(&[0xE4 ^ 0x34]);

        assert_eq!(result.data, expected.data);
    }

    #[test]
    fn test_map_bytewise_several_bytes() {
        let val1 = Value::from_bytes(&[0xE4, 0x22, 0x52, 0x43, 0x59]);
        let val2 = Value::from_bytes(&[0x34, 0x29, 0x00, 0x34, 0x42]);

        let result = val1.map_bytewise_masked(&val2, !0, |a, b| a ^ b);
        let expected = Value::from_bytes(&[
            0xE4 ^ 0x34,
            0x22 ^ 0x29,
            0x52 ^ 0x00,
            0x43 ^ 0x34,
            0x59 ^ 0x42,
        ]);

        assert_eq!(result.data, expected.data);
    }

    #[test]
    fn test_map_bytewise_several_bytes_partial_mask() {
        let val1 = Value::from_bytes(&[0xE4, 0x22, 0x52, 0x43, 0x59]);
        let val2 = Value::from_bytes(&[0x34, 0x29, 0x12, 0x34, 0x42]);

        let result = val1.map_bytewise_masked(&val2,  (1 << 3) - 1, |a, b| a ^ b);
        let expected = Value::from_bytes(&[
            0xE4 ^ 0x34,
            0x22 ^ 0x29,
            0x52 ^ 0x12,
            0x43,
            0x59,
        ]);

        assert_eq!(result.data, expected.data);
    }
}