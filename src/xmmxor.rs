use std::collections::{HashMap};
use iced_x86::{Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register};
use anyhow::Result;

use crate::analysis::{Analysis, AnalysisOpts, AnalysisResult, AnalysisResultType, AnalysisSet};
use crate::cfg::CFGAnalysisResult;
use crate::mem::{SimMemory, VecMemory};
use crate::loader::{Binary};
use crate::registers::{Value, get_reg_val, set_reg_val};

fn reg_as_str(formatter: &mut dyn Formatter,
                    reg: Register) -> &str {
    formatter.format_register(reg)
}

/// Check if a byte slice is likely a UTF-16 string.
/// Heuristics for a "likely UTF-16" string are:
/// - nonzero length
/// - any adjacent chars of the form \x00??, where ??
///   is any nonzero byte
fn likely_utf16(data: &[u8]) -> bool {
    let mut end = data.len();
    for i in (0..data.len() - 1).step_by(2) {
        if data[i] == 0x00 && data[i + 1] == 0x00 {
            end = i;
            break;
        }
    }

    if end == 0 {
        return false;
    }

    for i in (0..end - 1).step_by(4) {
        if data[i] != 0x00 && data[i + 1] == 0x00 && data[i + 2] != 0x00 && data[i + 3] == 0x00 {
            return true;
        }
    }

    false
}

fn u8_to_u16_le(input: &[u8]) -> Vec<u16> {
    assert!(input.len() % 2 == 0, "Length must be even");
    input.chunks_exact(2)
         .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
         .collect()
}

fn c_string_from_u8(bytes: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    let nul_position = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let slice = &bytes[..nul_position];
    String::from_utf8(slice.to_vec())
}

fn unicode_string_from_u8(bytes: &[u8]) -> Result<String, std::string::FromUtf16Error> {
    let as_unicode = u8_to_u16_le(bytes);
    let nul_position = as_unicode.iter().position(|&b| b == 0).unwrap_or(bytes.len() / 2);
    let slice = &as_unicode[..nul_position];
    String::from_utf16(slice)
}

pub struct DecodedString {
    pub encoding_size: u64,      // 2 if UTF-16, 1 if UTF-8
    pub text: String,
}

pub struct XorAnalysisResult {
    pub function_xor_strings: HashMap<u64, HashMap<u64, DecodedString>>,
}

impl AnalysisResult for XorAnalysisResult {
    fn get_type(&self) -> AnalysisResultType {
        AnalysisResultType::XmmXor
    }

    fn print_result(&self) {
        println!("[---------XmmXor Analysis--------]");
        let mut total_string_count = 0;
        for (func_start, strings) in self.function_xor_strings.iter() {
            println!("sub_{:X}", func_start);

            let mut xor_ips: Vec<_> = strings.keys().cloned().collect();
            xor_ips.sort();

            for ip in xor_ips {
                let xor_str = strings.get(&ip).unwrap();
                let encoding = match xor_str.encoding_size {
                    1 => "[ UTF-8  ]",
                    2 => "[ UTF-16 ]",
                    _ => "[ UNK    ]"
                };
                println!("{:X} -> {} \"{}\"", ip, encoding, xor_str.text);

                total_string_count += 1;
            }
        }

        println!("Total strings decoded: {}", total_string_count);
    }
}

fn load_operand(
    formatter: &mut dyn Formatter,
    regmap: &HashMap<String, Value>,
    vecmem: &VecMemory,
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
            let reg_val = get_reg_val( &regmap, reg_str);
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
                    match get_reg_val(&regmap, reg_str) {
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
            let result_count = vecmem.mem_read( reg_as_str(formatter, reg_base), total_offset as i64, &mut arr[0..memory_size]);
            
            if result_count == memory_size {
                Some((Value::from_bytes(&arr), memory_size))
            } else {
                None
            }
        },
        _ => None
    }
}

fn store_operand(
    formatter: &mut dyn Formatter,
    regmap: &mut HashMap<String, Value>,
    vecmem: &mut VecMemory,
    instruction: &Instruction,
    op: u32,
    value: &Value,
    size: usize
    )
{
    match instruction.op_kind(op) {
        OpKind::Register => {
            let reg_str = reg_as_str(formatter, instruction.op_register(op));
            set_reg_val(regmap, reg_str, value, size);
        },
        OpKind::Memory => {
            let reg_base = instruction.memory_base();
            let displacement = instruction.memory_displacement64() as usize;
            let reg_index = instruction.memory_index();
            let index_val = match reg_index {
                Register::None => Value::zero(),
                reg => {
                    let reg_str = reg_as_str(formatter, reg);
                    match get_reg_val(regmap, reg_str) {
                        Some(reg_val) => reg_val,
                        None => Value::zero(), // TODO: if we don't have a value for the index register then not actually possible to go forward
                    }
                }
            };
            let reg_index_size = reg_index.size();
            let scale = instruction.memory_index_scale() as usize;
            let total_offset = (index_val.as_zex_u64(reg_index_size) as usize) * scale + displacement;
            let memory_size = instruction.memory_size().size();

            vecmem.mem_write( reg_as_str(formatter, reg_base), total_offset as i64, &value.data[0..memory_size]);
        },
        _ => ()
    };
}

fn xor_values(val1: &Value, val2: &Value) -> Value {
    let data = val1.data
        .iter()
        .zip(val2.data.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    Value {
        data: data
    }
}

fn log_xor_result(decrypted_strings: &mut HashMap<u64, DecodedString>, result: &[u8], size: usize, instruction: &Instruction) {
    // We will try to interpret the string first as UTF-16.
    // If there is not a sensible decoding as UTF-16 then we will try as UTF-8.
    // We will consider a "sensible decoding" to be one in which 
    // the string has nonzero length after escaping special characters.
    // This will filter out most non-results, such as strings
    // which just consist of a single carriage return, etc.
    let is_zero = result[..size].iter().all(|x| *x == 0);

    if likely_utf16(result) && let Ok(as_unicode) = unicode_string_from_u8(result) {
        let unicode = as_unicode.escape_default().to_string();
        
        decrypted_strings.insert(instruction.ip(), DecodedString {
            encoding_size: 2, text: unicode
        });
    } else if !is_zero && let Ok(as_c_string) = c_string_from_u8(result) {
        let c_string = as_c_string.escape_default().to_string();

        if c_string.len() > 0 {
            decrypted_strings.insert(instruction.ip(), DecodedString {
                encoding_size: 1, text: c_string
            });
        }
    }
}

pub struct XorAnalysis {}

pub fn try_decrypt_xor(_opts: &AnalysisOpts, instructions: &[Instruction]) -> HashMap<u64, DecodedString> {
    let mut formatter = IntelFormatter::new();

    let mut regmap: HashMap<String, Value> = HashMap::new();
    let mut vecmem: VecMemory = VecMemory::new();

    let mut decrypted_strings: HashMap<u64, DecodedString> = HashMap::new();

    for instruction in instructions {
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
                let src = load_operand(&mut formatter, &regmap, &vecmem, instruction, 1);

                /* Only if we got some value based on the source operand */
                if let Some((src_val, src_size)) = &src {
                    /* Act depending on destination operand */
                    store_operand(&mut formatter, &mut regmap, &mut vecmem, instruction, 0, src_val, *src_size);
                }
            },
            Mnemonic::Xorps
            | Mnemonic::Xorpd
            | Mnemonic::Xor => {
                /* Determine source operand */
                let src = load_operand(&mut formatter, &regmap, &vecmem, instruction, 1);

                if instruction.op0_register() == instruction.op1_register() {

                } else if let Some((src_val, src_size)) = src {
                    // pretty sure only option is register in op0
                    if instruction.op0_kind() == OpKind::Register {
                        let op0_str = reg_as_str(&mut formatter, instruction.op0_register());

                        if let Some(dest_val) = get_reg_val(&mut regmap, op0_str) {
                            let result_val = xor_values(&dest_val, &src_val);
                            set_reg_val(&mut regmap, op0_str, &result_val, src_size);
                            
                            let result = &result_val.data;
                            log_xor_result(&mut decrypted_strings, result, src_size, &instruction);
                        }
                    }
                }
            },
            Mnemonic::Vxorps
            | Mnemonic::Vxorpd
            | Mnemonic::Vpxor
            | Mnemonic::Vpxord
            | Mnemonic::Vpxorq => {
                /* Determine source operands */
                let src1 = load_operand(&mut formatter, &regmap, &vecmem, instruction, 1);
                let src2 = load_operand(&mut formatter, &regmap, &vecmem, instruction, 2);

                if instruction.op0_register() == instruction.op1_register() && instruction.op1_register() == instruction.op2_register() {

                } else if let Some((src1_val, src1_size)) = src1 && let Some((src2_val, _src2_size)) = src2 {
                    // pretty sure only option is register in op0
                    if instruction.op0_kind() == OpKind::Register {
                        let result_val = xor_values(&src1_val, &src2_val);

                        let op0_str = reg_as_str(&mut formatter, instruction.op0_register());
                        set_reg_val(&mut regmap, op0_str, &result_val, src1_size);
                        
                        let result = &result_val.data;
                        log_xor_result(&mut decrypted_strings, result, src1_size, instruction);
                    }
                }
            }
            _ => ()
        };
    }

    decrypted_strings
}

impl Analysis for XorAnalysis {
    fn analyze(&self, analyses: &AnalysisSet, _binary: &Binary) -> Result<Box<dyn AnalysisResult>> {
        let cfg_result = analyses.get_of_type(AnalysisResultType::CFG)?
            .as_type::<CFGAnalysisResult>()?;

        let mut string_map: HashMap<u64, HashMap<u64, DecodedString>> = HashMap::new();

        for (&func_start, func_block) in cfg_result.function_blocks.iter() {
            for (&_block_start, basic_block) in &func_block.basic_blocks {
                let decrypted_strings = try_decrypt_xor(&analyses.opts, &basic_block.instructions);

                if decrypted_strings.len() > 0 {
                    string_map.entry(func_start).or_insert(HashMap::new()).extend(decrypted_strings);
                }
            }
        }

        Ok(Box::from(XorAnalysisResult{
            function_xor_strings: string_map,
        }))
    }
}