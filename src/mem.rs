use std::{collections::HashMap};

pub trait SimMemory {
    /// Write to emulated memory at [register+offset].
    /// Returns the number of bytes written.
    fn mem_write(&mut self, register: u64, offset: i64, bytes: &[u8]) -> usize;

    /// Read from emulated memory at [register+offset].
    /// Returns the number of bytes read.
    fn mem_read(&self, register: u64, offset: i64, bytes: &mut [u8]) -> usize;

    /// Shift all offsets for the submemory of `register`
    /// by `offset`.
    fn mem_shift(&mut self, register: u64, offset: i64);
}

struct SubChunk {
    pos: i64,
    data: Vec<u8>,
}

struct SubMemory {
    submap: Vec<SubChunk>,
}

pub struct VecMemory {
    memmap: HashMap<u64, Box<SubMemory>>,
}

impl VecMemory {
    pub fn new() -> Self {
        VecMemory {
            memmap: HashMap::new()
        }
    }
}

fn get_chunk<'a>(submem: &'a SubMemory, offset: i64) -> Option<&'a SubChunk> {
    for chunk in submem.submap.iter() {
        if chunk.pos == offset {
            return Some(chunk)
        }
    }

    None
}

fn get_chunk_mut<'a>(submem: &'a mut SubMemory, offset: i64) -> Option<&'a mut SubChunk> {
    for chunk in submem.submap.iter_mut() {
        if chunk.pos == offset {
            return Some(chunk)
        }
    }

    None
}

fn add_chunk<'a>(submem: &'a mut SubMemory, offset: i64) -> &'a mut SubChunk {
    submem.submap.push(SubChunk { pos: offset, data: Vec::new() });
    submem.submap.last_mut().unwrap() // guaranteed to exist after push
}

// SCENARIO 1: fits
// In this scenario, no modification needs to be done, we can simply return the slice directly.
// mem_start                               mem_start + data.len()
// |----------------------------------------|
//                    |---------------|
//                offset           offset + count

// SCENARIO 2: trailing overlap, need append
// mem_start                               mem_start + data.len()
// |----------------------------------------|
//                    |----------------------------------|
//                offset                          offset + count

// SCENARIO 3: leading overlap, need prepend
//                       mem_start                               mem_start + data.len()
//                       |----------------------------------------|
//              |----------------------------------|
//          offset                          offset + count

// SCENARIO 4: full overlap, need both prepend and append
//                       mem_start    mem_start + data.len()
//                       |-----------------|
//              |----------------------------------|
//          offset                          offset + count

/// Immutably attempt to touch an offset within the submemory.
/// If the data at `offset` exists and consists of at least `count` bytes, then
/// a tuple of the form (abs, rel) is returned, where:
///  - abs is the offset of the chunk (i.e. can be used to lookup the chunk in the submemory)
///  - rel is the position within the chunk where the start of `offset` is located.
/// Otherwise, None is returned.
fn touch_submap_offset(submem: &SubMemory, offset: i64, count: usize) -> Option<(i64, usize)> {
    for chunk in submem.submap.iter() {
        let mem_end = chunk.pos + chunk.data.len() as i64;

        if offset >= chunk.pos && offset + count as i64 <= mem_end {
            let rel_start = (offset - chunk.pos) as usize;
            return Some((chunk.pos, rel_start));
        }
    }

    None
}

/// Mutably attempt to touch an offset within the submemory.
/// If there is any existing chunk which overlaps the memory region, either leading or trailing,
/// then the chunk is extended as needed to accommodate `count` bytes. Existing data
/// is preserved at the correct position and size.
/// If an overlapping chunk is found, a tuple of the form (abs, rel) is returned, where:
///  - abs is the offset of the chunk (i.e. can be used to lookup the chunk in the submemory)
///  - rel is the position within the chunk where the start of `offset` is located.
/// If there is no such existing chunk, None is returned.
fn touch_submap_offset_mut(submem: &mut SubMemory, offset: i64, count: usize) -> Option<(i64, usize)> {
    for chunk in submem.submap.iter_mut() {
        let mem_end = chunk.pos + chunk.data.len() as i64;

        let overlaps_start = chunk.pos >= offset && chunk.pos <= offset + count as i64;
        let overlaps_end = mem_end >= offset && mem_end <= offset + count as i64;

        if offset >= chunk.pos && offset + count as i64 <= mem_end {
            let rel_start = (offset - chunk.pos) as usize;
            return Some((chunk.pos, rel_start));
        }
        
        if overlaps_start {
            let prepend_count = (chunk.pos - offset) as usize;
            let mut with_prepended = Vec::from_iter(std::iter::repeat_n(0 as u8, prepend_count));
            with_prepended.extend(chunk.data.iter());

            chunk.data = with_prepended;
            chunk.pos = offset;
        }

        if overlaps_end {
            let append_count = (offset + count as i64) - mem_end;
            chunk.data.extend(std::iter::repeat_n(0 as u8, append_count as usize));
        }

        if overlaps_start || overlaps_end {
            return Some((chunk.pos, (offset - chunk.pos) as usize));
        }
    }

    return None
}

/// Acquire an immutable reference to an area of sub memory pointed to by `offset` of size `count` bytes.
/// If the memory does not exist, or does not cover at least `count` bytes, returns None.
fn get_submap_offset<'a>(submem: &'a SubMemory, offset: i64, count: usize) -> Option<&'a [u8]> {
    let exis = touch_submap_offset(submem, offset, count);

    match exis {
        Some((pos, subpos)) => {
            let chunk = get_chunk(submem, pos).unwrap(); // guaranteed to exist if touch returned Some

            Some(&chunk.data[subpos..subpos + count])
        },
        None => None
    }
}

/// Acquire a reference to an area of sub memory pointed to by `offset` of size `count` bytes.
fn get_submap_offset_mut<'a>(submem: &'a mut SubMemory, offset: i64, count: usize) -> &'a mut [u8] {
    let exis = touch_submap_offset_mut(submem, offset, count);

    match exis {
        Some((pos, subpos)) => {
            let chunk = get_chunk_mut(submem, pos).unwrap(); // guaranteed to exist if touch returned Some

            return &mut chunk.data[subpos..subpos + count];
        },
        None => {
            let chunk = add_chunk(submem, offset);
            // fill the chunk with `count` zeros
            chunk.data.extend(std::iter::repeat_n(0, count));

            return &mut chunk.data[0..count];
        }
    }
}

impl SimMemory for VecMemory {
    fn mem_write(&mut self, register: u64, offset: i64, bytes: &[u8]) -> usize {
        let submem = self.memmap.entry(register).or_insert(
            Box::from(SubMemory {
                submap: Vec::new()
            })
        );

        let dest = get_submap_offset_mut(submem, offset, bytes.len());
        let min_size = dest.len().min(bytes.len());
        dest[0..min_size].copy_from_slice(&bytes[0..min_size]);
        min_size
    }

    fn mem_read(&self, register: u64, offset: i64, bytes: &mut [u8]) -> usize {
        match self.memmap.get(&register) {
            Some(submem) => {
                match get_submap_offset(submem, offset, bytes.len()) {
                    Some(src) => {
                        let min_size = bytes.len().min(src.len());
                        bytes[0..min_size].copy_from_slice(&src[0..min_size]);
                        min_size
                    },
                    None => 0
                }
            },
            None => 0
        }
    }

    fn mem_shift(&mut self, register: u64, offset: i64) {
        self.memmap.entry(register).and_modify(|submem| {
            submem.submap.iter_mut().for_each(|chunk| chunk.pos += offset);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submap_offset_mut_fits() {
        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x200, data: vec![0x20, 0x30, 0x40, 0x50] });

        // fits, no modification needed
        // offset overlaps memory start
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x200, 3), Some((0x200, 0)));

        // fits, no modification needed
        // offset does not overlap memory start,
        // should give us an offset into the memory block
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x201, 3), Some((0x200, 1)));
    }

    #[test]
    fn test_submap_offset_mut_fits_full() {
        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x200, data: vec![0x20, 0x30, 0x40, 0x50] });

        // fits, no modification needed
        // offset overlaps memory start
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x200, 4), Some((0x200, 0)));
    }

    #[test]
    fn test_submap_offset_mut_trailing() {
        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x200, data: vec![0x20, 0x30, 0x40, 0x50] });

        // scenario 2: trailing overlap, need append
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x202, 6), Some((0x200, 2)));
        // should have 8 elements afterward
        assert_eq!(get_chunk(&mut submem, 0x200).unwrap().data.len(), 8);
        // should have zero-extended elements
        assert!(get_chunk(&mut submem, 0x200).unwrap().data.eq(&vec![0x20, 0x30, 0x40, 0x50, 0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_submap_offset_mut_trailing_edge() {
        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x200, data: vec![0x20, 0x30, 0x40, 0x50] });

        // scenario 2b: trailing overlap, need append
        // In this scenario, only the very edge overlaps, but the touch
        // should still handle joining the memory
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x204, 2), Some((0x200, 4)));
        // should not have resulted in more than one chunk
        assert_eq!(submem.submap.len(), 1);
        // should have 6 elements afterward
        assert_eq!(get_chunk(&mut submem, 0x200).unwrap().data.len(), 6);
        // should have zero-extended elements
        assert!(get_chunk(&mut submem, 0x200).unwrap().data.eq(&vec![0x20, 0x30, 0x40, 0x50, 0x00, 0x00]));
    }

    #[test]
    fn test_submap_offset_mut_leading() {
        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x200, data: vec![0x20, 0x30, 0x40, 0x50] });

        // scenario 3: leading overlap, need prepend
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x1FC, 6), Some((0x1FC, 0)));
        // should have 8 elements afterward
        assert_eq!(get_chunk(&mut submem, 0x1FC).unwrap().data.len(), 8);
        // should have zero-prepended elements
        assert!(get_chunk(&mut submem, 0x1FC).unwrap().data.eq(&vec![0x00, 0x00, 0x00, 0x00, 0x20, 0x30, 0x40, 0x50]));
    }

    #[test]
    fn test_submap_offset_mut_leading_edge() {
        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x200, data: vec![0x20, 0x30, 0x40, 0x50] });

        // scenario 3b: leading overlap, need prepend
        // In this scenario, only the edges are exactly touching.
        // touch should still handle joining the memory
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x1FE, 6), Some((0x1FE, 0)));
        // should not have resulted in more than one chunk
        assert_eq!(submem.submap.len(), 1);
        // should have 6 elements afterward
        assert_eq!(get_chunk(&mut submem, 0x1FE).unwrap().data.len(), 6);
        // should have zero-prepended elements
        assert!(get_chunk(&mut submem, 0x1FE).unwrap().data.eq(&vec![0x00, 0x00, 0x20, 0x30, 0x40, 0x50]));
    }

    #[test]
    fn test_submap_offset_mut_trailing_leading() {
        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });

        // scenario 4: full overlap, need both prepend and append
        assert_eq!(touch_submap_offset_mut(&mut submem, 0x2FD, 9), Some((0x2FD, 0)));
        assert_eq!(get_chunk(&mut submem, 0x2FD).unwrap().data.len(), 9);
        // should have zero-extended and zero-prepended elements
        assert!(get_chunk(&mut submem, 0x2FD).unwrap().data.eq(&vec![0x00, 0x00, 0x00, 0x20, 0x30, 0x40, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_memory_read() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = Vec::from([0u8; 2]);
        let bytes_read = vecmem.mem_read(5, 0x300, &mut bytes);

        assert_eq!(bytes_read, 2);
        assert_eq!(bytes, vec![0x20, 0x30]);
    }

    #[test]
    fn test_memory_read_suboffset() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = Vec::from([0u8; 2]);
        let bytes_read = vecmem.mem_read(5, 0x301, &mut bytes);

        assert_eq!(bytes_read, 2);
        assert_eq!(bytes, vec![0x30, 0x40]);
    }

    #[test]
    fn test_memory_read_negative_register() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = Vec::from([0u8; 2]);
        let bytes_read = vecmem.mem_read(6, 0x300, &mut bytes);

        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn test_memory_read_negative_offset() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = Vec::from([0u8; 2]);
        let bytes_read = vecmem.mem_read(5, 0x400, &mut bytes);

        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn test_memory_read_negative_wrong_count() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = Vec::from([0u8; 4]);
        let bytes_read = vecmem.mem_read(5, 0x300, &mut bytes);

        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn test_memory_write() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = vec![0x55, 0x66];
        let bytes_written = vecmem.mem_write(5, 0x300, &mut bytes);

        assert_eq!(bytes_written, 2);

        let mut read_result = Vec::from([0u8; 3]);
        let bytes_read = vecmem.mem_read(5, 0x300, &mut read_result);

        assert_eq!(bytes_read, 3);
        assert_eq!(read_result, vec![0x55, 0x66, 0x40]);
    }

    #[test]
    fn test_memory_write_suboffs() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40, 0x50, 0x60] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = vec![0x55, 0x66];
        let bytes_written = vecmem.mem_write(5, 0x302, &mut bytes);

        assert_eq!(bytes_written, 2);

        let mut read_result = Vec::from([0u8; 5]);
        let bytes_read = vecmem.mem_read(5, 0x300, &mut read_result);

        assert_eq!(bytes_read, 5);
        assert_eq!(read_result, vec![0x20, 0x30, 0x55, 0x66, 0x60]);
    }

    #[test]
    fn test_memory_write_leading() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40, 0x50, 0x60] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = vec![0x55, 0x66];
        let bytes_written = vecmem.mem_write(5, 0x2FF, &mut bytes);

        assert_eq!(bytes_written, 2);

        let mut read_result = Vec::from([0u8; 6]);
        let bytes_read = vecmem.mem_read(5, 0x2FF, &mut read_result);

        assert_eq!(bytes_read, 6);
        assert_eq!(read_result, vec![0x55, 0x66, 0x30, 0x40, 0x50, 0x60]);
    }

    #[test]
    fn test_memory_write_trailing() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40, 0x50, 0x60] });
        vecmem.memmap.insert(5, Box::from(submem));

        let mut bytes = vec![0x55, 0x66];
        let bytes_written = vecmem.mem_write(5, 0x304, &mut bytes);

        assert_eq!(bytes_written, 2);

        let mut read_result = Vec::from([0u8; 6]);
        let bytes_read = vecmem.mem_read(5, 0x300, &mut read_result);

        assert_eq!(bytes_read, 6);
        assert_eq!(read_result, vec![0x20, 0x30, 0x40, 0x50, 0x55, 0x66]);
    }

    #[test]
    fn test_memory_shift() {
        let mut vecmem = VecMemory {
            memmap: HashMap::new()
        };

        let mut submem1: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem1.submap.push(SubChunk { pos: 0x300, data: vec![0x20, 0x30, 0x40] });
        submem1.submap.push(SubChunk { pos: 0x304, data: vec![0x60, 0x70, 0x80, 0x90] });
        vecmem.memmap.insert(5, Box::from(submem1));

        let mut submem2: SubMemory = SubMemory {
            submap: Vec::new(),
        };

        submem2.submap.push(SubChunk { pos: 0x300, data: vec![0x22, 0x33, 0x44] });
        vecmem.memmap.insert(7, Box::from(submem2));

        vecmem.mem_shift(5, 6);

        // first array should be at 0x306 now
        let mut read_result = Vec::from([0u8; 3]);
        let bytes_read = vecmem.mem_read(5, 0x306, &mut read_result);

        assert_eq!(bytes_read, 3);
        assert_eq!(read_result, vec![0x20, 0x30, 0x40]);

        // second array at 0x30A now
        let mut read_result = Vec::from([0u8; 4]);
        let bytes_read = vecmem.mem_read(5, 0x30A, &mut read_result);

        assert_eq!(bytes_read, 4);
        assert_eq!(read_result, vec![0x60, 0x70, 0x80, 0x90]);

        // data should not exist at original pos
        let mut read_result = Vec::from([0u8; 4]);
        let bytes_read = vecmem.mem_read(5, 0x300, &mut read_result);

        assert_eq!(bytes_read, 0);

        // second register should be unchanged
        let mut read_result = Vec::from([0u8; 3]);
        let bytes_read = vecmem.mem_read(7, 0x300, &mut read_result);

        assert_eq!(bytes_read, 3);
        assert_eq!(read_result, vec![0x22, 0x33, 0x44]);
    }
}