use std::collections::{HashMap};

pub fn get_reg_val(regmap: &HashMap<String, u128>,
                    reg: &str) -> Option<u128> {
    regmap.get(reg).copied()
}

pub fn set_reg_val(regmap: &mut HashMap<String, u128>,
                    reg: &str,
                    val: u128,
                    size: usize) {
    let exis: u128 = regmap.get(reg).copied().unwrap_or(0);
    let size_bits = size * 8;
    let mask: u128 = match size_bits {
        128 => !0,
        _ => (1 << size_bits) - 1
    };
    let mask_exis = exis & !mask;
    let mask_val = val & mask;
    let new_val = mask_exis | mask_val;
    regmap.insert(reg.to_string(), new_val);
}