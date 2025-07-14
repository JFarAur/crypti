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

fn reg_as_str(formatter: &mut dyn Formatter,
                    reg: Register) -> &str {
    // Get the full register, this way AL maps to the
    // same register as EAX, RAX, etc.
    formatter.format_register(reg.full_register())
}

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
    pub regmap: HashMap<String, Value>,
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
        formatter: &mut dyn Formatter,
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
                let reg_str = reg_as_str(formatter, instruction.op_register(op));
                let reg_val = get_reg_val( &self.regmap, reg_str);
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
                        let reg_str = reg_as_str(formatter, reg);
                        match get_reg_val(&self.regmap, reg_str) {
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
                let result_count = self.vecmem.mem_read( reg_as_str(formatter, reg_base), total_offset as i64, &mut arr[0..memory_size]);
                
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
        formatter: &mut dyn Formatter,
        instruction: &Instruction,
        op: u32,
        value: &Value,
        size: usize
        )
    {
        match instruction.op_kind(op) {
            OpKind::Register => {
                let reg_str = reg_as_str(formatter, instruction.op_register(op));
                set_reg_val(&mut self.regmap, reg_str, value, size);
            },
            OpKind::Memory => {
                let reg_base = instruction.memory_base();
                let displacement = instruction.memory_displacement64() as usize;
                let reg_index = instruction.memory_index();
                let index_val = match reg_index {
                    Register::None => Value::zero(),
                    reg => {
                        let reg_str = reg_as_str(formatter, reg);
                        match get_reg_val(&mut self.regmap, reg_str) {
                            Some(reg_val) => reg_val,
                            None => Value::zero(), // TODO: if we don't have a value for the index register then not actually possible to go forward
                        }
                    }
                };
                let reg_index_size = reg_index.size();
                let scale = instruction.memory_index_scale() as usize;
                let total_offset = (index_val.as_zex_u64(reg_index_size) as usize) * scale + displacement;
                let memory_size = instruction.memory_size().size();

                self.vecmem.mem_write( reg_as_str(formatter, reg_base), total_offset as i64, &value.data[0..memory_size]);
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
                    let src = self.load_operand(&mut formatter, instruction, 1);

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
                        self.store_operand(&mut formatter, instruction, 0, src_val, *src_size);
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
                    let src = self.load_operand(&mut formatter, instruction, 1);
                    let dest = self.load_operand(&mut formatter, instruction, 0);

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
                            self.store_operand(&mut formatter, instruction, 0, result_val, *result_size);

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
                    let src1 = self.load_operand(&mut formatter, instruction, 1);
                    let src2 = self.load_operand(&mut formatter, instruction, 2);
                    let dest = self.load_operand(&mut formatter, instruction, 0);

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
                            self.store_operand(&mut formatter, instruction, 0, result_val, *result_size);

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
    use super::*;

    #[test]
    fn test_emu_move_instruction() {
        let emu = Emulator::new();
        
        
    }
}