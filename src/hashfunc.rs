use std::collections::{HashMap, HashSet};
use iced_x86::{Instruction, Mnemonic, OpKind};
use anyhow::Result;

use crate::analysis::{Analysis, AnalysisOpts, AnalysisResult, AnalysisResultType, AnalysisSet};
use crate::cfg::{BasicBlock, CFGAnalysisResult};
use crate::emulator::{Emulator, ResultInfo, ReasonResult, EmulatorResult, EmulatorStopReason, InstructionClass};
use crate::loader::{Binary};
use crate::hashconst::{is_known_hash_func, known_factor_u32, known_factor_u64};

pub struct HashAnalysisResult {
    pub function_hash_algos: HashMap<u64, HashSet<String>>,
}

impl AnalysisResult for HashAnalysisResult {
    fn get_type(&self) -> AnalysisResultType {
        AnalysisResultType::Hash
    }

    fn print_result(&self) {
        println!("[---------Hashfunc Analysis--------]");
        for (func_start, hash_algos) in self.function_hash_algos.iter() {
            print!("sub_{:X}", func_start);
            let as_vec: Vec<String> = hash_algos.iter().map(|algo| algo.clone()).collect();
            println!(" -> {}", as_vec.join(","));
        }

        if self.function_hash_algos.len() == 0 {
            println!("No hash algorithms detected.");
        }
    }
}

pub struct HashAnalysis {}

pub fn try_hash_analysis(_opts: &AnalysisOpts, basic_block: &BasicBlock) -> HashSet<String> {
    let mut emu: Emulator = Emulator::new();
    let mut detected_algos: HashSet<String> = HashSet::new();
    let mut idx: usize = 0;

    for instruction in &basic_block.instructions {
        if instruction.mnemonic() == Mnemonic::Imul {
            if instruction.op2_kind() == OpKind::Immediate32 {
                if let Some(algo) = known_factor_u32(instruction.immediate32()) {
                    detected_algos.insert(algo);
                }
            } else if instruction.op2_kind() == OpKind::Immediate64 {
                if let Some(algo) = known_factor_u64(instruction.immediate64()) {
                    detected_algos.insert(algo);
                }
            }
        }
    }

    loop {
        let instructions: &[Instruction] = &basic_block.instructions[idx..basic_block.instructions.len()];

        let EmulatorResult{ 
            info: ResultInfo{ instructions_emulated },
            reason: reason_result
        } = emu.emulate_until(instructions, EmulatorStopReason::PostInstruction(InstructionClass::MovOrVectorMov));

        if let ReasonResult::InstructionResult(mov_result) = reason_result {
            if let (_instruction, Some((mov_data, mov_size))) = &mov_result {
                if let Some(hash_algo) = is_known_hash_func(mov_data, *mov_size) {
                    detected_algos.insert(hash_algo);
                }
            }
        } else if let ReasonResult::OutOfInstructions = reason_result {
            break;
        }

        idx += instructions_emulated;
    }


    detected_algos
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

impl Analysis for HashAnalysis {
    fn analyze(&self, analyses: &AnalysisSet, _binary: &Binary) -> Result<Box<dyn AnalysisResult>> {
        let cfg_result = analyses.get_of_type(AnalysisResultType::CFG)?
            .as_type::<CFGAnalysisResult>()?;

        let mut algos_map: HashMap<u64, HashSet<String>> = HashMap::new();

        for (&func_start, func_block) in cfg_result.function_blocks.iter() {
            if !func_block.basic_blocks.iter().any(| (_block_start, basic_block) | block_contains_xor(basic_block)) {
                continue;
            }

            for (&_block_start, basic_block) in &func_block.basic_blocks {
                let detected_algos = try_hash_analysis(&analyses.opts, basic_block);

                if detected_algos.len() > 0 {
                    algos_map.entry(func_start).or_insert(HashSet::new()).extend(detected_algos);
                }
            }
        }

        Ok(Box::from(HashAnalysisResult{
            function_hash_algos: algos_map,
        }))
    }
}