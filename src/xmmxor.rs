use std::collections::{HashMap};
use iced_x86::{Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register};
use anyhow::Result;

use crate::analysis::{Analysis, AnalysisOpts, AnalysisResult, AnalysisResultType, AnalysisSet};
use crate::cfg::CFGAnalysisResult;
use crate::log::LogLevel;
use crate::log_println;
use crate::mem::{SimMemory, VecMemory};
use crate::loader::{Binary};
use crate::registers::{get_reg_val, set_reg_val};

fn reg_as_str(formatter: &mut dyn Formatter,
                    reg: Register) -> &str {
    formatter.format_register(reg)
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

pub struct XorAnalysis {}

pub fn try_decrypt_xor(opts: &AnalysisOpts, instructions: &[Instruction]) -> HashMap<u64, DecodedString> {
    let mut formatter = IntelFormatter::new();

    let mut regmap: HashMap<String, u128> = HashMap::new();
    let mut vecmem: VecMemory = VecMemory::new();

    let mut decrypted_strings: HashMap<u64, DecodedString> = HashMap::new();

    for instruction in instructions {
        /* Determine source operand */
        let src = match instruction.op1_kind() {
            OpKind::Immediate32to64 => Some((instruction.immediate32to64() as u128, 8)),
            OpKind::Immediate64 => Some((instruction.immediate64() as u128, 8)),
            OpKind::Register => {
                let op1_str = reg_as_str(&mut formatter, instruction.op1_register());
                let reg_val = get_reg_val( &mut regmap, op1_str);
                match reg_val {
                    Some(val) => Some((val, instruction.op1_register().size())),
                    None => None
                }
            },
            OpKind::Memory => {
                let reg_base = instruction.memory_base();
                let displacement = instruction.memory_displacement64() as usize;
                let reg_index = instruction.memory_index();
                let index_val = match reg_index {
                    Register::None => 0,
                    reg => {
                        let reg_str = reg_as_str(&mut formatter, reg);
                        match get_reg_val(&mut regmap, reg_str) {
                            Some(reg_val) => reg_val as usize,
                            None => 0, // TODO: 0 is not a good guess, value is legitimately unknown
                        }
                    }
                };
                let scale = instruction.memory_index_scale() as usize;
                let total_offset = index_val * scale + displacement;

                // TODO: This scheme of storing values (using u128) means that 256-bit and 512-bit
                // registers and operations can't be supported.
                let memory_size = instruction.memory_size().size().min(16);

                let mut arr: [u8; 16] = [0; 16];
                let result_count = vecmem.mem_read( reg_as_str(&mut formatter, reg_base), total_offset as i64, &mut arr[0..memory_size]);
                
                if result_count == memory_size {
                    Some((u128::from_le_bytes(arr), memory_size))
                } else {
                    None
                }
            },
            _ => None
        };

        match instruction.mnemonic() {
            Mnemonic::Mov
            | Mnemonic::Movups
            | Mnemonic::Movaps
            | Mnemonic::Movss
            | Mnemonic::Movsd
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu
            | Mnemonic::Movapd
            | Mnemonic::Movupd => {
                /* Only if we got some value based on the source operand */
                if let Some((src_val, src_size)) = src {
                    /* Act depending on destination operand */
                    match instruction.op0_kind() {
                        OpKind::Register => {
                            let op0_str = reg_as_str(&mut formatter, instruction.op0_register());
                            set_reg_val(&mut regmap, op0_str, src_val, src_size);
                        },
                        OpKind::Memory => {
                            let reg_base = instruction.memory_base();
                            let displacement = instruction.memory_displacement64() as usize;
                            let reg_index = instruction.memory_index();
                            let index_val = match reg_index {
                                Register::None => 0,
                                reg => {
                                    let reg_str = reg_as_str(&mut formatter, reg);
                                    match get_reg_val(&mut regmap, reg_str) {
                                        Some(reg_val) => reg_val as usize,
                                        None => 0, // TODO: if we don't have a value for the index register then not actually possible to go forward
                                    }
                                }
                            };
                            let scale = instruction.memory_index_scale() as usize;
                            let total_offset = index_val * scale + displacement;
                            let memory_size = instruction.memory_size().size();

                            vecmem.mem_write( reg_as_str(&mut formatter, reg_base), total_offset as i64, &src_val.to_le_bytes()[0..memory_size]);
                        },
                        _ => ()
                    };
                }
            },
            Mnemonic::Xorps
            | Mnemonic::Xorpd
            | Mnemonic::Xor => {
                if instruction.op0_register() == instruction.op1_register() {

                } else if let Some((src_val, src_size)) = src {
                    // pretty sure only option is register in op0
                    match instruction.op0_kind() {
                        OpKind::Register => {
                            let op0_str = reg_as_str(&mut formatter, instruction.op0_register());

                            if let Some(reg_val) = get_reg_val(&mut regmap, op0_str) {
                                let result_val = src_val ^ reg_val;

                                set_reg_val(&mut regmap, op0_str, result_val, src_size);
                                
                                let result = result_val.to_le_bytes();
                                let is_zero = result[..src_size].iter().all(|x| *x == 0);

                                // We will try to interpret the string first as UTF-8.
                                // If there is not a sensible decoding as UTF-8 then we will try as UTF-16.
                                // We will consider a "sensible decoding" to be one in which 
                                // the string has nonzero length after escaping special characters.
                                // This will filter out most non-results, such as strings
                                // which just consist of a single carriage return, etc.

                                if !is_zero && let Ok(as_c_string) = c_string_from_u8(&result) {
                                    let c_string = as_c_string.escape_default().to_string();

                                    if c_string.len() > 0 {
                                        decrypted_strings.insert(instruction.ip(), DecodedString {
                                            encoding_size: 1, text: c_string
                                        });
                                    } else if let Ok(as_unicode) = unicode_string_from_u8(&result) {
                                        let unicode = as_unicode.escape_default().to_string();
                                        if unicode.len() > 0 {
                                            decrypted_strings.insert(instruction.ip(), DecodedString {
                                                encoding_size: 2, text: unicode
                                            });
                                        } else {
                                            log_println!(opts.log_level, LogLevel::Debug, "No sensible decoding for xor result at {:X}", instruction.ip());
                                        }
                                    }
                                }
                            }
                        },
                        _ => ()
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