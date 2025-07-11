use std::collections::{HashMap, HashSet};
use anyhow::{Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

use crate::analysis::{AnalysisResult, AnalysisResultType, Analysis, AnalysisSet};
use crate::loader::{Binary};
use crate::log::{LogLevel};
use crate::log_println;

pub struct CFGAnalysis {}

#[allow(dead_code)]
#[derive(Clone)]
pub struct BasicBlock {
    pub virtual_start: u64,
    pub instructions: Vec<Instruction>,
    pub targets: Vec<u64>,
}

impl BasicBlock {
    /// Get the total size of this basic block, in bytes.
    /// Returns the sum of sizes of all instructions in the basic block.
    pub fn len(&self) -> usize {
        self.instructions.iter().map(|insn| insn.len()).sum()
    }
}

#[allow(dead_code)]
pub struct FunctionBlock {
    pub virtual_start: u64,
    pub size: usize,
    pub basic_blocks: HashMap<u64, BasicBlock>
}

#[allow(dead_code)]
pub struct CFGAnalysisResult {
    pub instructions: Vec<Instruction>,
    pub virt_to_idx: HashMap<u64, usize>,
    pub function_blocks: HashMap<u64, FunctionBlock>,
    pub call_destinations: Vec<u64>,
}

impl AnalysisResult for CFGAnalysisResult {
    fn get_type(&self) -> AnalysisResultType {
        AnalysisResultType::CFG
    }

    fn print_result(&self) {
        println!("[----------CFG Analysis----------]");
        println!("Decoded {} instructions.", self.instructions.len());
        println!("Found {} function candidates.", self.call_destinations.len());
        println!("Identified {} function blocks.", self.function_blocks.len());
    }
}

#[derive(Debug, Clone)]
struct VecPatch<T> {
    start_idx: usize,
    end_idx: usize,
    patch: Vec<T>,
}

/// Apply a set of vec patches to a vec.
/// Requires that `patches` contains no overlaps.
fn apply_vec_patches<T: Copy>(dest: &Vec<T>, vec_patches: &Vec<VecPatch<T>>) -> Vec<T> {
    let mut sorted_patches = vec_patches.clone();
    sorted_patches.sort_by(|a, b| a.start_idx.cmp(&b.start_idx));

    let mut newvec: Vec<T> = Vec::new();

    let mut current_start: usize = 0;
    for vec_patch in sorted_patches {
        newvec.extend_from_slice(&dest[current_start..vec_patch.start_idx]);
        newvec.extend(&vec_patch.patch);
        current_start = vec_patch.end_idx;
    }

    newvec.extend_from_slice(&dest[current_start..]);

    newvec
}

impl Analysis for CFGAnalysis {
    fn analyze(&self, analyses: &AnalysisSet, binary: &Binary) -> Result<Box<dyn AnalysisResult>> {
        let mut virt_to_idx: HashMap<u64, usize> = HashMap::new();
        let mut instructions: Vec<Instruction> = Vec::new();
        let mut call_destinations_set: HashSet<u64> = HashSet::new();

        // Entry point should be a call destination.
        call_destinations_set.insert(binary.entry_point);

        let mut instruction = Instruction::default();

        for code_seg in binary.code_segs.iter() {
            // DECODE INSTRUCTIONS - first pass.
            // We will make a simple decoding pass and decode the entire segment at once.
            // This is not completely accurate, because the code segment may contain some
            // non-code data (jump tables).
            let mut decoder = Decoder::with_ip(
                binary.bitness,
                code_seg.buf(&binary.filebuf),
                code_seg.virtual_start,
                DecoderOptions::NONE
            );

            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);

                if instruction.is_call_near() {
                    let call_dest = instruction.near_branch_target();

                    // record calls only within the current code segment
                    if call_dest >= code_seg.virtual_start && call_dest < code_seg.virtual_start + code_seg.size {
                        call_destinations_set.insert(call_dest);
                    }
                }

                let current_idx = instructions.len();
                virt_to_idx.insert(instruction.ip(), current_idx);
                instructions.push(instruction);
            }
        }

        // DECODE INSTRUCTIONS - second pass.
        // First pass is indiscriminate and decodes the entire segment at once.
        // Due to possible presence of non-code data (e.g. jump tables)
        // in the code segment, this may result in some misalignment, causing
        // analysis to fail on some functions.
        // We can find bad functions by looking up call destinations in
        // virt_to_idx - if we didn't decode an instruction at that exact IP,
        // then this is a big clue of misalignment.
        let mut bad_functions: Vec<u64> = Vec::new();
        for call_dest in call_destinations_set.iter() {
            if let None = virt_to_idx.get(&call_dest) {
                bad_functions.push(*call_dest);
            }
        }

        let mut vec_patches: Vec<VecPatch<Instruction>> = Vec::new();

        for &function_start in bad_functions.iter() {
            let containing_seg = binary
                .containing_segment(function_start);

            if containing_seg.is_none() {
                log_println!(analyses.opts.log_level, LogLevel::Warn, "Warning: unable to fix misaligned function starting at {:X}", function_start);
                log_println!(analyses.opts.log_level, LogLevel::Warn, "No code segment that contains call target {:X}", function_start);
                log_println!(analyses.opts.log_level, LogLevel::Warn, "(May indicate packing or polymorphic code)");

                continue;
            }

            let code_seg = containing_seg.unwrap();
            let actual_start = code_seg.virt_to_phys(function_start);

            let mut decoder = Decoder::with_ip(
                binary.bitness,
                &code_seg.buf(&binary.filebuf)[actual_start..],
                function_start,
                DecoderOptions::NONE
            );

            let mut fixed_instructions: Vec<Instruction> = Vec::new();
            let mut fixed_part_end: Option<usize> = None;

            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);

                // once we start decoding instructions with IPs in our lookup table,
                // we know we have alignment again
                if let Some(idx) = virt_to_idx.get(&instruction.ip()) {
                    fixed_part_end = Some(*idx);
                    break;
                }

                fixed_instructions.push(instruction);
            }

            if fixed_part_end.is_none() {
                log_println!(analyses.opts.log_level, LogLevel::Warn, "Warning: unable to fix misaligned function starting at {:X}", function_start);
                log_println!(analyses.opts.log_level, LogLevel::Warn, "Unable to determine a subsequent realigned point.");
                // This should be insanely rare

                continue;
            }

            let patch_end_idx = fixed_part_end.unwrap();

            // Try to find the index of the old instruction that overlaps the function start.
            let nearest_start_idx = (&instructions[..patch_end_idx])
            .iter()
            .enumerate()
            .rev()
            .find_map(|(idx, instruction)| {
                let lies_after_start = function_start >= instruction.ip();
                let lies_before_end = function_start < instruction.ip() + instruction.len() as u64;
                if lies_after_start && lies_before_end {
                    return Some(idx);
                } else {
                    return None;
                }
            });

            if nearest_start_idx.is_none() {
                log_println!(analyses.opts.log_level, LogLevel::Warn, "Warning: unable to fix misaligned function starting at {:X}", function_start);
                log_println!(analyses.opts.log_level, LogLevel::Warn, "Unable to determine the preceding instruction.");
                // This should be insanely rare

                continue;
            }

            let patch_start_idx = nearest_start_idx.unwrap();

            // At this point, we have a vec fixed_instructions which we need
            // to use to patch the following slice of the instructions vec:
            // 
            // |-----------------------|
            // patch_start_idx        patch_end_idx
            // 
            // Problem is, there may be more than one bad function which needs patching.
            // We have to save all patches and apply them all at once.
            vec_patches.push(VecPatch {
                start_idx: patch_start_idx,
                end_idx: patch_end_idx,
                patch: fixed_instructions
            });
        }

        log_println!(analyses.opts.log_level, LogLevel::Debug, "Applying {} function decoding fixes.", vec_patches.len());

        instructions = apply_vec_patches(&instructions, &vec_patches);

        // now we applied the decoding patches. However, the virt_to_idx
        // table is out-of-date, we need to recreate it.

        virt_to_idx.clear();

        for (i, instruction) in instructions.iter().enumerate() {
            virt_to_idx.insert(instruction.ip(), i);
        }

        // FIND FUNCTION BLOCKS

        let mut function_blocks: HashMap<u64, FunctionBlock> = HashMap::new();

        // if opt is set to restrict to just one function, then
        // use that specific function block, else form a vec from the call destinations
        // set and sort it
        let mut call_destinations = match analyses.opts.restrict_function_block {
            Some(restrict_function_block) => Vec::from_iter(std::iter::once(restrict_function_block)),
            None => Vec::from_iter(call_destinations_set.iter().copied())
        };
        call_destinations.sort();

        let mut fun_iter = call_destinations.iter().peekable();

        while let Some(&call_dest_virt) = fun_iter.next() {
            match virt_to_idx.get(&call_dest_virt) {
                Some(&idx) => {
                    let func_start = call_dest_virt;
                    let mut func_end: Option<u64> = None;
                    let mut block_start = call_dest_virt;
                    let mut block: Vec<Instruction> = Vec::new();
                    let mut basic_blocks: HashMap<u64, BasicBlock> = HashMap::new();

                    let last_idx = match fun_iter.peek() {
                        Some(&last_addr) => match virt_to_idx.get(last_addr) {
                            Some(&asdf) => asdf,
                            None => instructions.len()
                        },
                        None => instructions.len(),
                    };

                    for i in idx..last_idx {
                        instruction = instructions[i];
                        block.push(instruction);

                        if instruction.mnemonic() == Mnemonic::Int3 {
                            if block.len() > 0 {
                                basic_blocks.insert(block_start, BasicBlock {
                                    virtual_start: block_start,
                                    instructions: block,
                                    targets: Vec::new()
                                });
                            }
                            
                            func_end = Some(instruction.next_ip());

                            break;
                        } else if instruction.mnemonic() == Mnemonic::Ret ||
                            instruction.is_jmp_short_or_near() ||
                            instruction.is_jmp_near_indirect() {

                            let mut targets: Vec<u64> = Vec::new();

                            if instruction.is_jmp_short_or_near() {
                                let target = instruction.memory_displacement64();
                                targets.push(target);
                            }

                            // TODO: indirect jmps are not handled yet

                            basic_blocks.insert(block_start, BasicBlock{
                                virtual_start: block_start,
                                instructions: block,
                                targets: Vec::new()
                            });
                            block = Vec::new();
                            block_start = instruction.next_ip();

                            func_end = Some(instruction.next_ip());
                        } else if instruction.is_jcc_short_or_near() ||
                                    instruction.is_jcx_short() {

                            let mut targets: Vec<u64> = Vec::new();

                            // next instruction
                            targets.push(instruction.next_ip());

                            // conditional branch target
                            let target = instruction.memory_displacement64();
                            targets.push(target);

                            basic_blocks.insert(block_start, BasicBlock{
                                virtual_start: block_start,
                                instructions: block,
                                targets: targets
                            });
                            block = Vec::new();
                            block_start = instruction.next_ip();
                        }
                    }

                    if let Some(restrict_basic_block) = analyses.opts.restrict_basic_block {
                        basic_blocks = {
                            let mut block_map: HashMap<u64, BasicBlock> = HashMap::new();
                            let maybe_block = 
                                basic_blocks
                                .iter()
                                .find(|(_, basic_block)| {
                                    let lies_after_start = restrict_basic_block >= basic_block.virtual_start;
                                    let lies_before_end = restrict_basic_block < basic_block.virtual_start + basic_block.len() as u64;
                                    lies_after_start && lies_before_end
                                    })
                            ;
                            if maybe_block.is_some() {
                                let (start_addr, basic_block) = maybe_block.unwrap();
                                block_map.insert(*start_addr, basic_block.clone());
                            }
                            block_map
                        };
                    }

                    // now, if we successfully resolved the end of the function,
                    // and the function has at least one basic block, add it.
                    if let Some(func_end_virt) = func_end {
                        if basic_blocks.len() > 0 {
                            function_blocks.insert(func_start, FunctionBlock {
                                virtual_start: func_start,
                                size: (func_end_virt - func_start) as usize,
                                basic_blocks: basic_blocks
                            });
                        }
                    } else {
                        log_println!(analyses.opts.log_level, LogLevel::Warn, "Warning: Failed to resolve end of function starting at {:016X}", func_start);
                    }
                },
                None => {
                    log_println!(analyses.opts.log_level, LogLevel::Warn, "Warning: No instruction index for virtual address {:016X}", call_dest_virt);
                }
            }
        }

        Ok(Box::from(CFGAnalysisResult{
            instructions: instructions,
            virt_to_idx: virt_to_idx,
            function_blocks: function_blocks,
            call_destinations: call_destinations,
        }))
    }
}