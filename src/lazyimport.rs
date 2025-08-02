use std::collections::HashMap;
use iced_x86::{Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register};
use anyhow::Result;

use crate::analysis::{Analysis, AnalysisOpts, AnalysisResult, AnalysisResultType, AnalysisSet};
use crate::cfg::CFGAnalysisResult;
use crate::hashfunc::HashAnalysisResult;
use crate::loader::Binary;
use crate::hashfind::find_api_hash_seeded;
use crate::fnv::fnv32_hash_str;

pub struct LazyImportBlock {
    pub peb_access: Instruction,
    pub indirect_call: Option<Instruction>,

    pub mov_32_imm: Vec<Instruction>,
    pub cmp_32_imm: Vec<Instruction>,
    pub api_name: Option<String>,
}

pub struct LazyImportAnalysisResult {
    pub func_import_blocks: HashMap<u64, Vec<LazyImportBlock>>,
}

impl AnalysisResult for LazyImportAnalysisResult {
    fn get_type(&self) -> AnalysisResultType {
        AnalysisResultType::LazyImport
    }

    fn print_result(&self) {
        println!("[-------LazyImport Analysis--------]");
        let mut total_import_count = 0;
        let mut formatter = IntelFormatter::new();
        for (func_start, lazy_imports) in self.func_import_blocks.iter() {
            println!("sub_{:X}", func_start);

            for imported_block in lazy_imports {
                let peb_access_fmt = {
                    let mut instruction: String = "".to_string();
                    formatter.format(&imported_block.peb_access, &mut instruction);
                    instruction
                };

                println!("  {:X}   {}", imported_block.peb_access.ip(), peb_access_fmt);

                if let Some(indirect_call) = imported_block.indirect_call {
                    if let Some(mov_32_imm) = imported_block.mov_32_imm.last() {
                        let mov_32_imm_fmt = {
                            let mut instruction: String = "".to_string();
                            formatter.format(&mov_32_imm, &mut instruction);
                            instruction
                        };

                        println!("  {:X}.. {}", mov_32_imm.ip(), mov_32_imm_fmt);
                    }

                    if let Some(cmp_32_imm) = imported_block.cmp_32_imm.last() {
                        let cmp_32_imm_fmt = {
                            let mut instruction: String = "".to_string();
                            formatter.format(&cmp_32_imm, &mut instruction);
                            instruction
                        };

                        println!("  {:X}.. {} -> \"{}\"", cmp_32_imm.ip(), cmp_32_imm_fmt, imported_block.api_name.as_ref().unwrap_or(&"???".to_string()));
                    }

                    let indirect_call_fmt = {
                        let mut instruction: String = "".to_string();
                        formatter.format(&indirect_call, &mut instruction);
                        instruction
                    };

                    println!("  {:X}...{}", indirect_call.ip(), indirect_call_fmt);
                }

                total_import_count += 1;
            }
        }

        if total_import_count == 0 {
            println!("No hash-based lazy imports detected.");
        } else {
            println!("Total hash-based lazy imports found: {}", total_import_count);
        }
    }
}

pub struct LazyImportAnalysis {}

fn instruction_is_peb_access(bitness: u32, instruction: &Instruction) -> bool {
    if instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Memory 
    {
        let is_tib = match bitness {
            64 => instruction.segment_prefix() == Register::GS,
            _ => instruction.segment_prefix() == Register::FS,
        };

        if is_tib {
            let no_pointer_arithmetic = instruction.memory_base() == Register::None && instruction.memory_index() == Register::None;

            let is_peb = match bitness {
                64 => instruction.memory_displacement64() == 0x60,
                _ => instruction.memory_displacement32() == 0x30,
            };

            return no_pointer_arithmetic && is_peb;
        }
    }

    false
}

pub fn try_lazy_import_analysis(_opts: &AnalysisOpts, binary: &Binary, instructions: &[Instruction]) -> Vec<LazyImportBlock> {
    let mut lazy_import_blocks: Vec<LazyImportBlock> = Vec::new();
    let mut current_last_block: Option<&mut LazyImportBlock> = None;

    for instruction in instructions.iter() {
        if instruction_is_peb_access(binary.bitness, instruction) {
            lazy_import_blocks.push(LazyImportBlock {
                peb_access: *instruction,
                indirect_call: None,
                mov_32_imm: Vec::new(),
                cmp_32_imm: Vec::new(),
                api_name: None,
            });

            current_last_block = lazy_import_blocks.last_mut();
        }

        if let Some(last_block) = &mut current_last_block {
            let is_mov_32_imm = instruction.mnemonic() == Mnemonic::Mov && instruction.op1_kind() == OpKind::Immediate32;

            if is_mov_32_imm {
                last_block.mov_32_imm.push(*instruction);
            }

            if last_block.mov_32_imm.len() > 0 {
                let is_cmp_32_imm = instruction.mnemonic() == Mnemonic::Cmp && instruction.op1_kind() == OpKind::Immediate32;

                if is_cmp_32_imm {
                    last_block.cmp_32_imm.push(*instruction);
                }
            }
        }
            
        let is_call_indirect = instruction.mnemonic() == Mnemonic::Call && instruction.is_call_near_indirect();

        if is_call_indirect {
            if let Some(last_block) = &mut current_last_block {
                last_block.indirect_call = Some(*instruction);
            }

            current_last_block = None;
        }
    }

    for block in &mut lazy_import_blocks {
        if block.indirect_call.is_some() {
            if block.mov_32_imm.len() != 1 {
                continue;
            }

            if block.cmp_32_imm.len() != 1 {
                continue;
            }

            let mov_32_imm = block.mov_32_imm.last().unwrap();
            let cmp_32_imm = block.cmp_32_imm.last().unwrap();

            let seed = mov_32_imm.immediate32();
            let hash = cmp_32_imm.immediate32();

            if let Some(api_name) = find_api_hash_seeded(seed, hash, fnv32_hash_str) {
                block.api_name = Some(api_name.to_string());
            }
        }
    }

    lazy_import_blocks
}

impl Analysis for LazyImportAnalysis {
    fn analyze(&self, analyses: &AnalysisSet, binary: &Binary) -> Result<Box<dyn AnalysisResult>> {
        let cfg_result = analyses.get_of_type(AnalysisResultType::CFG)?
            .as_type::<CFGAnalysisResult>()?;
        let algos_result = analyses.get_of_type(AnalysisResultType::Hash)?
            .as_type::<HashAnalysisResult>()?;

        let mut func_lazy_imports: HashMap<u64, Vec<LazyImportBlock>> = HashMap::new();

        for (hash_func, hash_algos) in &algos_result.function_hash_algos {
            if !hash_algos.contains("FNV/32") {
                continue;
            }

            if let Some(func_block) = &cfg_result.function_blocks.get(hash_func) {
                func_lazy_imports.insert(*hash_func, try_lazy_import_analysis(&analyses.opts, binary, &func_block.instructions));
            }
        }

        Ok(Box::from(LazyImportAnalysisResult{
            func_import_blocks: func_lazy_imports,
        }))
    }
}