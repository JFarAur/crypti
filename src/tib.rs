use iced_x86::Register;

use crate::{mem::{SimMemory, VecMemory}};

const MEM_REGION_TIB: u8 = 0x1u8 << 1;
const MEM_REGION_PEB: u8 = 0x1u8 << 2;
const MEM_REGION_LDR: u8 = 0x1u8 << 3;

const TIB_ABSOLUTE_ADDRESS: u64 = 0x1000;
const PEB_ABSOLUTE_ADDRESS: u64 = 0x3000;
const LDR_ABSOLUTE_ADDRESS: u64 = 0x4000;

pub fn install_tib(bitness: u32, vecmem: &mut VecMemory) {
    vecmem.mem_mark(Register::None as u64, TIB_ABSOLUTE_ADDRESS as i64, 0x2000, MEM_REGION_TIB);
    vecmem.mem_mark(Register::None as u64, PEB_ABSOLUTE_ADDRESS as i64, 0x1000, MEM_REGION_PEB);
    vecmem.mem_mark(Register::None as u64, LDR_ABSOLUTE_ADDRESS as i64, 0x100, MEM_REGION_LDR);

    if bitness == 64 {
        vecmem.mem_write(Register::None as u64, TIB_ABSOLUTE_ADDRESS as i64 + 0x60, &PEB_ABSOLUTE_ADDRESS.to_le_bytes());
        vecmem.mem_write(Register::None as u64, PEB_ABSOLUTE_ADDRESS as i64 + 0x18, &LDR_ABSOLUTE_ADDRESS.to_le_bytes());
    } else {
        vecmem.mem_write(Register::None as u64, TIB_ABSOLUTE_ADDRESS as i64 + 0x30, &PEB_ABSOLUTE_ADDRESS.to_le_bytes());
        vecmem.mem_write(Register::None as u64, PEB_ABSOLUTE_ADDRESS as i64 + 0x0C, &LDR_ABSOLUTE_ADDRESS.to_le_bytes());
    }
}