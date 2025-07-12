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