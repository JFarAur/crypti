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
    Nothing,
}

pub struct ResultInfo {
    pub instructions_emulated: usize,
}

#[allow(dead_code)]
pub enum ReasonResult {
    InstructionParameters((Instruction, HashMap<String, MaybeValue>)),
    InstructionResult((Instruction, MaybeValue)),
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

impl Emulator {
    pub fn new() -> Emulator {
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
        op: u32) -> Option<(Value, usize)>
    {
        match instruction.op_kind(op) {
            OpKind::Immediate8 => Some((Value::from_bytes(&instruction.immediate8().to_le_bytes()), 1)),
            OpKind::Immediate8_2nd => Some((Value::from_bytes(&instruction.immediate8_2nd().to_le_bytes()), 1)),
            OpKind::Immediate8to16 => Some((Value::from_bytes(&instruction.immediate8to16().to_le_bytes()), 2)),
            OpKind::Immediate8to32 => Some((Value::from_bytes(&instruction.immediate8to32().to_le_bytes()), 4)),
            OpKind::Immediate8to64 => Some((Value::from_bytes(&instruction.immediate8to64().to_le_bytes()), 8)),
            OpKind::Immediate16 => Some((Value::from_bytes(&instruction.immediate16().to_le_bytes()), 2)),
            OpKind::Immediate32 => Some((Value::from_bytes(&instruction.immediate32().to_le_bytes()), 4)),
            OpKind::Immediate32to64 => Some((Value::from_bytes(&instruction.immediate32to64().to_le_bytes()), 8)),
            OpKind::Immediate64 => Some((Value::from_bytes(&instruction.immediate64().to_le_bytes()), 8)),
            OpKind::Register => {
                let reg_val = get_reg_val( &self.regmap, instruction.op_register(op) as u64);
                match reg_val {
                    Some(val) => Some((val, instruction.op_register(op).size())),
                    None => None
                }
            },
            OpKind::Memory => {
                let reg_base = instruction.memory_base();
                let displacement = instruction.memory_displacement64() as usize;
                let reg_index = instruction.memory_index();
                let index_val = match reg_index {
                    Register::None => Value::zero(),
                    reg => {
                        match get_reg_val(&self.regmap, reg as u64) {
                            Some(reg_val) => reg_val,
                            None => Value::zero(), // TODO: 0 is not a good guess, value is legitimately unknown
                        }
                    }
                };
                let reg_index_size = reg_index.size();
                let scale = instruction.memory_index_scale() as usize;

                let total_offset = (index_val.as_zex_u64(reg_index_size) as usize) * scale + displacement;
                let memory_size = instruction.memory_size().size().min(64);

                let mut arr: [u8; 64] = [0; 64];
                let result_count = self.vecmem.mem_read( reg_base as u64, total_offset as i64, &mut arr[0..memory_size]);
                
                if result_count == memory_size {
                    Some((Value::from_bytes(&arr), memory_size))
                } else {
                    None
                }
            },
            _ => None
        }
    }

    pub fn store_operand(
        &mut self,
        instruction: &Instruction,
        op: u32,
        value: &Value,
        size: usize
        )
    {
        match instruction.op_kind(op) {
            OpKind::Register => {
                set_reg_val(&mut self.regmap, instruction.op_register(op) as u64, value, size);
            },
            OpKind::Memory => {
                let reg_base = instruction.memory_base();
                let displacement = instruction.memory_displacement64() as usize;
                let reg_index = instruction.memory_index();
                let index_val = match reg_index {
                    Register::None => Value::zero(),
                    reg => {
                        match get_reg_val(&mut self.regmap, reg as u64) {
                            Some(reg_val) => reg_val,
                            None => Value::zero(), // TODO: if we don't have a value for the index register then not actually possible to go forward
                        }
                    }
                };
                let reg_index_size = reg_index.size();
                let scale = instruction.memory_index_scale() as usize;
                let total_offset = (index_val.as_zex_u64(reg_index_size) as usize) * scale + displacement;
                let memory_size = instruction.memory_size().size();

                self.vecmem.mem_write( reg_base as u64, total_offset as i64, &value.data[0..memory_size]);
            },
            _ => ()
        };
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
                        let ops = vec![(1, src)];
                        let params: HashMap<String, MaybeValue> = self.process_operands(&mut formatter, instruction, &ops);

                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx },
                            reason: ReasonResult::InstructionParameters((*instruction, params))
                        };
                    }

                    /* Only if we got some value based on the source operand */
                    if let Some((src_val, src_size)) = &src {
                        /* Act depending on destination operand */
                        self.store_operand(instruction, 0, src_val, *src_size);
                    }

                    /* If there is a post instruction type set, return with the result. */
                    if let EmulatorStopReason::PostInstruction(InstructionClass::MovOrVectorMov) = stop_reason {
                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx + 1 },
                            reason: ReasonResult::InstructionResult((*instruction, src))
                        };
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

                        let ops = vec![(0, dest), (1, src)];
                        let params: HashMap<String, MaybeValue> = self.process_operands(&mut formatter, instruction, &ops);

                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx },
                            reason: ReasonResult::InstructionParameters((*instruction, params))
                        };
                    }

                    let result: MaybeValue = dest.as_ref()
                        .zip(src.as_ref())
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

                        let ops = vec![(0, dest), (1, src1), (2, src2)];
                        let params: HashMap<String, MaybeValue> = self.process_operands(&mut formatter, instruction, &ops);

                        return EmulatorResult {
                            info: ResultInfo { instructions_emulated: instruction_idx },
                            reason: ReasonResult::InstructionParameters((*instruction, params))
                        };
                    }

                    let result: MaybeValue = src1.as_ref()
                        .zip(src2.as_ref())
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
                }
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
        let mut emu = Emulator::new();

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
}