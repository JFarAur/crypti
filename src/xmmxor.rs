use std::collections::{HashMap};
use iced_x86::{Instruction, Mnemonic};
use anyhow::Result;

use crate::analysis::{Analysis, AnalysisOpts, AnalysisResult, AnalysisResultType, AnalysisSet};
use crate::cfg::{BasicBlock, CFGAnalysisResult};
use crate::emulator::{Emulator, ResultInfo, ReasonResult, EmulatorResult, EmulatorStopReason, InstructionClass};
use crate::hashfunc::HashAnalysisResult;
use crate::loader::{Binary};

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
    pub function_annotations: HashMap<u64, String>,
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

            if let Some(func_annotation) = self.function_annotations.get(func_start) {
                println!("Detections: {}", func_annotation);
            }

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

pub fn try_decrypt_xor(_opts: &AnalysisOpts, basic_block: &BasicBlock) -> HashMap<u64, DecodedString> {
    let mut emu: Emulator = Emulator::new();
    let mut decrypted_strings: HashMap<u64, DecodedString> = HashMap::new();
    let mut idx: usize = 0;

    loop {
        let instructions: &[Instruction] = &basic_block.instructions[idx..basic_block.instructions.len()];

        let EmulatorResult{ 
            info: ResultInfo{ instructions_emulated },
            reason: reason_result
        } = emu.emulate_until(instructions, EmulatorStopReason::PostInstruction(InstructionClass::XorOrVectorXor));

        if let ReasonResult::InstructionResult(xor_result) = reason_result {
            if let (instruction, Some((xor_data, xor_size))) = &xor_result {
                if xor_data.data[0] != 0 {
                    log_xor_result(&mut decrypted_strings, &xor_data.data, *xor_size, instruction);
                }
            }
        } else if let ReasonResult::OutOfInstructions = reason_result {
            break;
        }

        idx += instructions_emulated;
    }


    decrypted_strings
}

fn block_contains_xor(basic_block: &BasicBlock) -> bool {
    let is_xor = |instruction: &Instruction| {
        match instruction.mnemonic() {
            Mnemonic::Xor
            | Mnemonic::Xorps
            | Mnemonic::Xorpd
            | Mnemonic::Vxorps
            | Mnemonic::Vxorpd
            | Mnemonic::Vpxor
            | Mnemonic::Vpxord
            | Mnemonic::Vpxorq => true,
            _ => false
        }
    };

    basic_block.instructions.iter().find(|&instruction| is_xor(instruction)).is_some()
}

impl Analysis for XorAnalysis {
    fn analyze(&self, analyses: &AnalysisSet, _binary: &Binary) -> Result<Box<dyn AnalysisResult>> {
        let cfg_result = analyses.get_of_type(AnalysisResultType::CFG)?
            .as_type::<CFGAnalysisResult>()?;
        let hash_result = analyses.get_of_type(AnalysisResultType::Hash)?
            .as_type::<HashAnalysisResult>()?;

        let mut string_map: HashMap<u64, HashMap<u64, DecodedString>> = HashMap::new();
        let mut function_annotations: HashMap<u64, String> = HashMap::new();

        for (&func_start, func_block) in cfg_result.function_blocks.iter() {
            for (&_block_start, basic_block) in &func_block.basic_blocks {
                if !block_contains_xor(basic_block) { continue; }

                let decrypted_strings = try_decrypt_xor(&analyses.opts, basic_block);

                if decrypted_strings.len() > 0 {
                    string_map.entry(func_start).or_insert(HashMap::new()).extend(decrypted_strings);
                }
            }

            if let Some(hash_algos) = hash_result.function_hash_algos.get(&func_start) {
                let as_vec: Vec<String> = hash_algos.iter().map(|algo| algo.clone()).collect();
                function_annotations.entry(func_start).or_insert(as_vec.join(","));
            }
        }

        Ok(Box::from(XorAnalysisResult{
            function_xor_strings: string_map,
            function_annotations: function_annotations
        }))
    }
}