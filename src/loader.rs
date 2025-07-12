use std::{fs};
use goblin::pe::{section_table, PE};
use anyhow::{anyhow, Result};

pub struct Segment {
    pub virtual_start: u64,     // base address of the segment (absolute virtual)
    pub phys_start: usize,      // base address of the segment (physical within filebuf)
    pub size: u64,              // size of the segment (physical)
}

impl Segment {
    /// Get the slice of the file buffer corresponding to this segment.
    pub fn buf<'a>(&self, filebuf: &'a [u8]) -> &'a [u8] {
        return &filebuf[self.phys_start..self.phys_start + self.size as usize];
    }

    /// Translate a virtual address to a physical address within the segment's data buffer.
    /// The result is ONLY VALID if the virtual address actually lies within the segment.
    /// If a virtual address outside the segment is provided, the result of this function
    /// will be INVALID.
    /// 
    /// If you aren't sure if a virtual address lies within the segment, consider
    /// using has_virt_addr first.
    pub fn virt_to_phys(&self, virt: u64) -> usize {
        (virt - self.virtual_start) as usize
    }

    /// Translate a physical address within the segment's data buffer to a virtual address.
    /// ONLY VALID if the physical address actually lies within the segment.
    /// If a physical address outside the segment is provided, the result of this function
    /// will be INVALID.
    /// 
    /// If you aren't sure if a physical address lies within the segment, check
    /// against the segment's size first.
    #[allow(dead_code)]
    pub fn phys_to_virt(&self, phys: usize) -> u64 {
        phys as u64 + self.virtual_start
    }

    /// Check whether a virtual address lies within this segment.
    /// 
    /// Returns true if `virt` lies in the segment, false otherwise.
    pub fn has_virt_addr(&self, virt: u64) -> bool {
        virt >= self.virtual_start && virt < self.virtual_start + self.size
    }
}

pub struct Binary {
    pub filebuf: Vec<u8>,
    pub code_segs: Vec<Segment>,
    pub bitness: u32,
    pub entry_point: u64,
    pub runtime_funcs: Vec<u64>,
}

impl Binary {
    /// Returns the segment containing a given virtual address.
    pub fn containing_segment<'a>(&'a self, virt: u64) -> Option<&'a Segment> {
        self.code_segs.iter().find(|&seg| seg.has_virt_addr(virt))
    }
}

#[allow(dead_code)]
fn get_runtime_functions(pe: &PE) -> Result<Vec<u64>> {
    let dir = pe.exception_data.as_ref().ok_or(anyhow!("No exception directory found for binary"))?;

    let functions = dir.functions().map_while(|func_entry| {
        match func_entry {
            Ok(entry) => Some(entry.begin_address as u64 + pe.image_base),
            Err(_) => None
        }
    }).collect();
    
    Ok(functions)
}

pub fn load_pe_file(file_path: &str) -> Result<Binary> {
    println!("[-------------Loader-------------]");
    println!("Loading {}", file_path);
    let mut pebin = Binary{
        filebuf: fs::read(file_path)?,
        code_segs: Vec::new(),
        bitness: 0,
        entry_point: 0,
        runtime_funcs: Vec::new(),
    };

    println!("Parsing PE.");
    let pe = PE::parse(&pebin.filebuf)?;
    pebin.bitness = if pe.is_64 { 64 } else { 32 };
    pebin.entry_point = pe.entry as u64 + pe.image_base;
    
    println!("{}-bit Windows binary.", pebin.bitness);

    println!("Code sections:");

    for section in &pe.sections {
        if section.characteristics & section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
            println!(
                "  {:<8} : RVA 0x{:08X}, size 0x{:08X} ({} bytes)",
                section.name().unwrap_or(""),
                section.virtual_address,
                section.virtual_size,
                section.virtual_size
            );

            let sec_start = section.pointer_to_raw_data as usize;

            let code_seg = Segment {
                virtual_start: section.virtual_address as u64 + pe.image_base,
                phys_start: sec_start,
                size: section.size_of_raw_data as u64,
            };

            pebin.code_segs.push(code_seg);
        }
    }

    let mut runtime_funcs = get_runtime_functions(&pe);
    match &mut runtime_funcs {
        Ok(funcs) => pebin.runtime_funcs.append(funcs),
        Err(err) => println!("Warning: {}", err)
    }

    Ok(pebin)
}