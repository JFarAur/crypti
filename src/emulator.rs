use std::collections::{HashMap, HashSet};
use iced_x86::{Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register};
use crate::mem::{SimMemory, VecMemory};
use crate::registers::{Value, get_reg_val, set_reg_val};

/// `Some(val, size)` is a known value corresponding to the lowest `size`
/// bytes of `val`.
/// 
/// `None` is an unknown value; the operand had no known value prior to
/// being read.
type MaybeValue = Option<(Value, usize)>;

#[allow(dead_code)]
pub enum InstructionClass {
    MovOrVectorMov,
    XorOrVectorXor,
}

#[allow(dead_code)]
pub enum EmulatorStopReason {
    PreInstruction(InstructionClass),
    PostInstruction(InstructionClass),
    FlaggedMemoryRead(u8),
    FlaggedMemoryWrite(u8),
    Nothing,
}

pub struct ResultInfo {
    pub instructions_emulated: usize,
}

#[allow(dead_code)]
pub enum ReasonResult {
    InstructionParameters((Instruction, HashMap<String, MaybeValue>)),
    InstructionResult((Instruction, MaybeValue)),
    FlaggedMemoryRead((u64, MaybeValue)),
    FlaggedMemoryWrite((u64, MaybeValue)),
    OutOfInstructions,
}

pub struct EmulatorResult {
    pub info: ResultInfo,
    pub reason: ReasonResult,
}

pub struct Emulator {
    pub regmap: HashMap<u64, Value>,
    pub vecmem: VecMemory,
    ignore_once: HashSet<u64>,
}

pub fn get_register_idx(reg: Register) -> u64 {
    reg.full_register() as u64
}

pub fn get_register_low_or_high(reg: Register) -> usize {
    match reg {
        Register::AH
        | Register::BH
        | Register::CH
        | Register::DH => 1,
        _ => 0
    }
}

pub enum OpLoadResult {
    Register((Register, MaybeValue)),
    Memory((Option<u64>, MaybeValue)),
    Immediate(MaybeValue),
    Nothing(MaybeValue),
}

impl OpLoadResult {
    pub fn value(&self) -> &MaybeValue {
        match self {
            OpLoadResult::Register((_, value)) => value,
            OpLoadResult::Memory((_, value)) => value,
            OpLoadResult::Immediate(value) => value,
            OpLoadResult::Nothing(value) => value,
        }
    }
}
pub enum OpStoreResult {
    Register((Register, usize)),
    Memory((Option<u64>, usize)),
    Nothing,
}

impl Emulator {
    pub fn new(_bitness: u32) -> Emulator {
        Emulator { 
            regmap: HashMap::new(),
            vecmem: VecMemory::new(),
            ignore_once: HashSet::new(),
        }
    }

    pub fn fmt_operand(
        &self,
        formatter: &mut dyn Formatter,
        instruction: &Instruction,
        op: u32) -> String
    {
        let mut output: String = String::new();

        if let Err(_err) = formatter.format_operand(instruction, &mut output, op) {
            return "<UNKNOWN VALUE>".to_string();
        }

        output
    }

    pub fn load_operand(
        &self,
        instruction: &Instruction,
        op: u32) -> OpLoadResult
    {
        match instruction.op_kind(op) {
            OpKind::Immediate8 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate8().to_le_bytes()), 1))),
            OpKind::Immediate8_2nd => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate8_2nd().to_le_bytes()), 1))),
            OpKind::Immediate8to16 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate8to16().to_le_bytes()), 2))),
            OpKind::Immediate8to32 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate8to32().to_le_bytes()), 4))),
            OpKind::Immediate8to64 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate8to64().to_le_bytes()), 8))),
            OpKind::Immediate16 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate16().to_le_bytes()), 2))),
            OpKind::Immediate32 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate32().to_le_bytes()), 4))),
            OpKind::Immediate32to64 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate32to64().to_le_bytes()), 8))),
            OpKind::Immediate64 => OpLoadResult::Immediate(Some((Value::from_bytes(&instruction.immediate64().to_le_bytes()), 8))),
            OpKind::Register => {
                let op_reg = instruction.op_register(op);
                let lowhigh = get_register_low_or_high(op_reg);
                let reg_val = get_reg_val( &self.regmap, get_register_idx(op_reg), lowhigh);
                match reg_val {
                    Some(val) => OpLoadResult::Register((op_reg, Some((val, instruction.op_register(op).size())))),
                    None => OpLoadResult::Register((op_reg, None))
                }
            },
            OpKind::Memory => {
                let reg_base = instruction.memory_base();
                let displacement = instruction.memory_displacement64() as usize;
                let reg_index = instruction.memory_index();
                let index_val = match reg_index {
                    Register::None => Value::zero(),
                    reg => {
                        // TODO: Pretty sure that a high-byte register (aka AH, BH, CH, DH) can not possibly
                        // be used for memory addressing, could be worth double checking.
                        match get_reg_val(&self.regmap, reg as u64, 0) {
                            Some(reg_val) => reg_val,
                            None => Value::zero(), // TODO: 0 is not a good guess, value is legitimately unknown
                        }
                    }
                };
                let reg_index_size = reg_index.size();
                let scale = instruction.memory_index_scale() as usize;

                // TODO: Not accurate emulation, but good enough for our purposes right now
                let index_times_scale = (index_val.as_zex_u64(reg_index_size) as usize).checked_mul(scale).unwrap_or_default();
                let total_offset = index_times_scale.checked_add(displacement).unwrap_or_default();
                let memory_size = instruction.memory_size().size().min(64);

                let mut arr: [u8; 64] = [0; 64];
                let result_count = self.vecmem.mem_read( reg_base as u64, total_offset as i64, &mut arr[0..memory_size]);
                
                let absolute_address = get_reg_val(&self.regmap, get_register_idx(reg_base), 0)
                    .and_then(|x| x.as_zex_u64(8).checked_add(total_offset as u64));

                if result_count == memory_size {
                    OpLoadResult::Memory((absolute_address, Some((Value::from_bytes(&arr), memory_size))))
                } else {
                    OpLoadResult::Memory((absolute_address, None))
                }
            },
            _ => OpLoadResult::Nothing(None)
        }
    }

    pub fn store_operand(
        &mut self,
        instruction: &Instruction,
        op: u32,
        value: &Value,
        size: usize
        ) -> OpStoreResult
    {
        match instruction.op_kind(op) {
            OpKind::Register => {
                let op_reg = instruction.op_register(op);
                let lowhigh = get_register_low_or_high(op_reg);
                set_reg_val(&mut self.regmap, get_register_idx(op_reg), value, size, lowhigh);

                OpStoreResult::Register((op_reg, size))
            },
            OpKind::Memory => {
                let reg_base = instruction.memory_base();
                let displacement = instruction.memory_displacement64() as usize;
                let reg_index = instruction.memory_index();
                let index_val = match reg_index {
                    Register::None => Value::zero(),
                    reg => {
                        // TODO: Pretty sure that a high-byte register (aka AH, BH, CH, DH) can not possibly
                        // be used for memory addressing, could be worth double checking.
                        match get_reg_val(&mut self.regmap, reg as u64, 0) {
                            Some(reg_val) => reg_val,
                            None => Value::zero(), // TODO: if we don't have a value for the index register then not actually possible to go forward
                        }
                    }
                };
                let reg_index_size = reg_index.size();
                let scale = instruction.memory_index_scale() as usize;
                // TODO: Not accurate emulation, but good enough for our purposes right now
                let index_times_scale = (index_val.as_zex_u64(reg_index_size) as usize).checked_mul(scale).unwrap_or_default();
                let total_offset = index_times_scale.checked_add(displacement).unwrap_or_default();
                let memory_size = instruction.memory_size().size();

                self.vecmem.mem_write( reg_base as u64, total_offset as i64, &value.data[0..memory_size]);

                let absolute_address = get_reg_val(&self.regmap, get_register_idx(reg_base), 0)
                    .and_then(|x| x.as_zex_u64(8).checked_add(total_offset as u64));

                OpStoreResult::Memory((absolute_address, size))
            },
            _ => OpStoreResult::Nothing
        }
    }

    pub fn process_operands(&self,
        formatter: &mut dyn Formatter,
        instruction: &Instruction,
        ops: &Vec<(u32, MaybeValue)>) -> HashMap<String, MaybeValue>
    {
        let mut params: HashMap<String, MaybeValue> = HashMap::new();

        for (op, val) in ops.iter().by_ref() {
            let src_op_fmt = self.fmt_operand(formatter, instruction, *op);
            params.insert(src_op_fmt, *val);
        }

        params
    }

    /// Start emulating until the condition described by `stop_reason` is reached,
    /// or the emulator runs through all the instructions in `ìnstructions`.
    pub fn emulate_until(&mut self, instructions: &[Instruction], stop_reason: EmulatorStopReason) -> EmulatorResult {
        let mut formatter = IntelFormatter::new();

        for (instruction_idx, instruction) in instructions.iter().enumerate().peekable() {
            match instruction.mnemonic() {
                Mnemonic::Mov
                | Mnemonic::Movups
                | Mnemonic::Movaps
                | Mnemonic::Movdqa
                | Mnemonic::Movdqu
                | Mnemonic::Movapd
                | Mnemonic::Movupd
                | Mnemonic::Vmovups
                | Mnemonic::Vmovupd
                | Mnemonic::Vmovdqa
                | Mnemonic::Vmovdqu
                | Mnemonic::Vmovaps
                | Mnemonic::Vmovapd => {
                    /* Determine source operand */
                    let src = self.load_operand(instruction, 1);

                    /* If there is a pre instruction type set and this instruction is not in the ignore list
                     (it was not previously processed by us in the last iteration) then return. */
                    if let EmulatorStopReason::PreInstruction(InstructionClass::MovOrVectorMov) = stop_reason {
                        let ops = vec![(1, *src.value())];
                        let params: HashMap<String, MaybeValue> = self.process_operands(&mut formatter, instruction, &ops);

                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx },
                            reason: ReasonResult::InstructionParameters((*instruction, params))
                        };
                    }

                    /* Only if we got some value based on the source operand */
                    let dest = if let Some((src_val, src_size)) = src.value() {
                        /* Act depending on destination operand */
                        self.store_operand(instruction, 0, src_val, *src_size)
                    } else {
                        OpStoreResult::Nothing
                    };

                    /* If there is a post instruction type set, return with the result. */
                    if let EmulatorStopReason::PostInstruction(InstructionClass::MovOrVectorMov) = stop_reason {
                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx + 1 },
                            reason: ReasonResult::InstructionResult((*instruction, *src.value()))
                        };
                    }

                    if let EmulatorStopReason::FlaggedMemoryRead(flag) = stop_reason {
                        if let OpLoadResult::Memory((Some(loc), Some((value, size)))) = src {
                            if self.vecmem.mem_is_marked(Register::None as u64, loc as i64, size, flag) {
                                return EmulatorResult {
                                    info: ResultInfo { instructions_emulated: instruction_idx + 1 },
                                    reason: ReasonResult::FlaggedMemoryRead((loc, Some((value, size)))),
                                };
                            }
                        }
                    } else if let EmulatorStopReason::FlaggedMemoryWrite(flag) = stop_reason {
                        if let OpStoreResult::Memory((Some(loc), size)) = dest {
                            if self.vecmem.mem_is_marked(Register::None as u64, loc as i64, size, flag) {
                                return EmulatorResult {
                                    info: ResultInfo { instructions_emulated: instruction_idx + 1 },
                                    reason: ReasonResult::FlaggedMemoryWrite((loc, *src.value())),
                                };
                            }
                        }
                    }
                },
                Mnemonic::Xorps
                | Mnemonic::Xorpd
                | Mnemonic::Xor => {
                    /* Determine source operand */
                    let src = self.load_operand(instruction, 1);
                    let dest = self.load_operand(instruction, 0);

                    if let EmulatorStopReason::PreInstruction(InstructionClass::XorOrVectorXor) = stop_reason {
                        self.ignore_once.insert(instruction.ip());

                        let ops = vec![(0, *dest.value()), (1, *src.value())];
                        let params: HashMap<String, MaybeValue> = self.process_operands(&mut formatter, instruction, &ops);

                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx },
                            reason: ReasonResult::InstructionParameters((*instruction, params))
                        };
                    }

                    let result: MaybeValue = dest.value().as_ref()
                        .zip(src.value().as_ref())
                        .map(|((dest_val, dest_size), (src_val, src_size))| {
                            let minsize: usize = (*dest_size).min(*src_size);
                            let mask: u64 = if *src_size == 64 { !0 } else { (1 << minsize) - 1 };
                            (dest_val.map_bytewise_masked(src_val, mask, |x, y| x ^ y), minsize)
                        });

                    match &result {
                        Some((result_val, result_size)) => {
                            self.store_operand(instruction, 0, result_val, *result_size);

                        },
                        None => (),
                    }

                    if let EmulatorStopReason::PostInstruction(InstructionClass::XorOrVectorXor) = stop_reason {
                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx + 1 },
                            reason: ReasonResult::InstructionResult((*instruction, result))
                        };
                    }
                    
                },
                Mnemonic::Vxorps
                | Mnemonic::Vxorpd
                | Mnemonic::Vpxor
                | Mnemonic::Vpxord
                | Mnemonic::Vpxorq => {
                    /* Determine source operands */
                    let src1 = self.load_operand(instruction, 1);
                    let src2 = self.load_operand(instruction, 2);
                    let dest = self.load_operand(instruction, 0);

                    if let EmulatorStopReason::PreInstruction(InstructionClass::XorOrVectorXor) = stop_reason {
                        self.ignore_once.insert(instruction.ip());

                        let ops = vec![(0, *dest.value()), (1, *src1.value()), (2, *src2.value())];
                        let params: HashMap<String, MaybeValue> = self.process_operands(&mut formatter, instruction, &ops);

                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx },
                            reason: ReasonResult::InstructionParameters((*instruction, params))
                        };
                    }

                    let result: MaybeValue = src1.value().as_ref()
                        .zip(src2.value().as_ref())
                        .map(|((dest_val, dest_size), (src_val, src_size))| {
                            let minsize: usize = (*dest_size).min(*src_size);
                            let mask: u64 = if *src_size == 64 { !0 } else { (1 << minsize) - 1 };
                            (dest_val.map_bytewise_masked(src_val, mask, |x, y| x ^ y), minsize)
                        });

                    match &result {
                        Some((result_val, result_size)) => {
                            self.store_operand(instruction, 0, result_val, *result_size);

                        },
                        None => (),
                    }

                    if let EmulatorStopReason::PostInstruction(InstructionClass::XorOrVectorXor) = stop_reason {
                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx + 1 },
                            reason: ReasonResult::InstructionResult((*instruction, result))
                        };
                    }
                },
                _ => ()
            };
        }

        EmulatorResult {
            info: ResultInfo { instructions_emulated: instructions.len() },
            reason: ReasonResult::OutOfInstructions
        }
    }
}

#[cfg(test)]
mod tests {
    use iced_x86::{Code, MemoryOperand};

    use super::*;

    #[test]
    fn test_emu_move_instruction() {
        // Test some different mov instructions,
        // some with immediate operands, some with
        // register operands, some with memory operands.
        let mut emu = Emulator::new(64);

        // mov rax, 0x50
        // mov rbx, 0xFFFFFF0
        // mov rcx, 2040
        // mov qword [rbp+0x60], rcx
        // mov rdx, qword [rbp+0x60]
        let instructions = vec![
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 0x50).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RBX, 0xFFFFFF0).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, 2040).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, MemoryOperand::with_base_displ(Register::RBP, 0x60), Register::RCX).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, MemoryOperand::with_base_displ(Register::RBP, 0x60)).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::R8, Register::RDX).unwrap(),
        ];

        const RAX: u64 = Register::RAX as u64;
        const RBX: u64 = Register::RBX as u64;
        const RBP: u64 = Register::RBP as u64;
        const R8: u64 = Register::R8 as u64;

        let EmulatorResult { info, reason: _reason }
            = emu.emulate_until(&instructions, EmulatorStopReason::Nothing);

        // all instructions emulated successfully
        assert_eq!(info.instructions_emulated, 6);
        
        // test if mov reg, imm worked
        assert_eq!(emu.regmap.get(&RAX).unwrap().as_zex_u64(8), 0x50);
        assert_eq!(emu.regmap.get(&RBX).unwrap().as_zex_u64(8), 0xFFFFFF0);

        // test if mov mem, reg and mov reg, mem work
        let mut memval = Value::from_bytes(&[0x00u8; 8]);
        emu.vecmem.mem_read(RBP, 0x60, &mut memval.data[0..8]);
        assert_eq!(memval.as_zex_u64(8), 2040);

        // test if mov reg, reg works
        assert_eq!(emu.regmap.get(&R8).unwrap().as_zex_u64(8), 2040);
    }

    #[test]
    fn test_emu_move_instruction_same_reg_diff_size_low() {
        // Test some mov instructions that use the same register,
        // but different operand sizes (e.g. AL and RAX, should modify the same register).
        // Only test when the smaller register is the least-significant portion
        // of the largest register.
        let mut emu = Emulator::new(64);

        // mov rax, 0x500000
        // mov al, 0x20
        let instructions = vec![
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 0x500000).unwrap(),
            Instruction::with2(Code::Mov_r8_imm8, Register::AL, 0x20).unwrap(),
        ];

        const RAX: u64 = Register::RAX as u64;

        let EmulatorResult { info, reason: _reason }
            = emu.emulate_until(&instructions, EmulatorStopReason::Nothing);

        // all instructions emulated successfully
        assert_eq!(info.instructions_emulated, 2);
        
        // test if emulation was correct
        assert_eq!(emu.regmap.get(&RAX).unwrap().as_zex_u64(8), 0x500020);
    }

    #[test]
    fn test_emu_move_instruction_same_reg_diff_size_high() {
        // Test some mov instructions that use the same register,
        // but different operand sizes (e.g. AH and RAX, should modify the same register).
        // Test when a high-byte register is used, which should
        // affect the correct byte in the larger register.
        let mut emu = Emulator::new(64);

        // mov rax, 0x500000
        // mov ah, 0x20
        let instructions = vec![
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 0x500000).unwrap(),
            Instruction::with2(Code::Mov_r8_imm8, Register::AH, 0x20).unwrap(),
        ];

        const RAX: u64 = Register::RAX as u64;

        let EmulatorResult { info, reason: _reason }
            = emu.emulate_until(&instructions, EmulatorStopReason::Nothing);

        // all instructions emulated successfully
        assert_eq!(info.instructions_emulated, 2);
        
        // test if emulation was correct
        assert_eq!(emu.regmap.get(&RAX).unwrap().as_zex_u64(8), 0x502000);
    }
}