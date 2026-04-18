use crate::mem::ProcessHandle;
use super::offsets::*;
use std::collections::HashMap;

/// Block cache: maps block index -> raw bytes of that block.
struct BlockCache {
    blocks: HashMap<u32, Vec<u8>>,
    /// Max bytes per block: 0xFFFF * stride + max_entry_size.
    block_size: usize,
}

impl BlockCache {
    fn new(stride: usize) -> Self {
        // Each block holds up to FNAME_POOL_OFFSET_UNITS offset units.
        // byte_offset = offset * stride, so max = 0xFFFF * stride.
        // Add room for the largest possible entry.
        let block_size = FNAME_POOL_OFFSET_UNITS * stride + MAX_NAME_LEN;
        Self {
            blocks: HashMap::new(),
            block_size,
        }
    }

    fn get_or_read(
        &mut self,
        proc: &ProcessHandle,
        block_ptrs: &[usize],
        block_idx: u32,
    ) -> Option<&[u8]> {
        if !self.blocks.contains_key(&block_idx) {
            let ptr = *block_ptrs.get(block_idx as usize)?;
            if ptr == 0 {
                return None;
            }
            let data = proc.read_bytes(ptr, self.block_size)?;
            self.blocks.insert(block_idx, data);
        }
        self.blocks.get(&block_idx).map(|v| v.as_slice())
    }
}

pub struct FNamePool {
    block_ptrs: Vec<usize>,
    cache: BlockCache,
    /// Stride per offset unit (2 for shipping, 4 for case-preserving/editor).
    stride: usize,
    /// Header byte offset (0 for shipping, 4 for case-preserving).
    header_off: usize,
    /// Shift to extract length from header (6 for shipping, 1 for case-preserving).
    len_shift: u32,
}

impl FNamePool {
    /// Initialize with an explicit GNames address.
    ///
    /// The scanner ([`crate::scanner::scan`]) produces this address by
    /// finding an FNameEntryAllocator whose block 0 decodes to `"None"`.
    pub fn with_addr(proc: &ProcessHandle, gnames_addr: usize) -> Option<Self> {
        // GNames might point directly to FNameEntryAllocator, or to an enclosing
        // FNamePool (with hash shards before the allocator), or be a pointer that
        // needs dereferencing. Try all of these.
        //
        // For each candidate allocator base, Blocks[] starts at +0x10.
        // Validate by reading Block[0] and checking that index 0 decodes to "None".

        let candidates = build_candidates(proc, gnames_addr);

        for (label, alloc_base) in &candidates {
            let blocks_base = alloc_base + 0x10;

            // Read Block[0] pointer
            let block0 = match proc.ptr(blocks_base) {
                Some(p) if p > MIN_VALID_PTR => p,
                _ => continue,
            };

            // Try to read entry 0 from block 0 and see if it decodes to "None"
            let data = match proc.read_bytes(block0, 256) {
                Some(d) => d,
                None => continue,
            };

            // Shipping format: stride=2, header at +0, len = header >> 6
            if try_decode_none(&data, 0, 6) {
                println!("[+] FNamePool found via {label} (shipping format, allocator @ {alloc_base:#X})");
                let block_ptrs = read_block_ptrs(proc, blocks_base);
                return Some(Self {
                    block_ptrs,
                    cache: BlockCache::new(2),
                    stride: 2,
                    header_off: 0,
                    len_shift: 6,
                });
            }

            // Case-preserving format: stride=4, header at +4, len = header >> 1
            if try_decode_none(&data, 4, 1) {
                println!("[+] FNamePool found via {label} (case-preserving format, allocator @ {alloc_base:#X})");
                let block_ptrs = read_block_ptrs(proc, blocks_base);
                return Some(Self {
                    block_ptrs,
                    cache: BlockCache::new(4),
                    stride: 4,
                    header_off: 4,
                    len_shift: 1,
                });
            }
        }

        eprintln!("[!] Could not locate FNameEntryAllocator. Tried {} candidates.", candidates.len());
        None
    }

    /// Resolve an FName from its raw memory representation (comparison index + number).
    /// `fname_addr` points to the FName struct: u32 ComparisonIndex, u32 Number.
    pub fn resolve(&mut self, proc: &ProcessHandle, fname_addr: usize) -> Option<String> {
        let comparison_idx = proc.read::<u32>(fname_addr)?;
        let number = proc.read::<u32>(fname_addr + 4)?;
        self.resolve_index(proc, comparison_idx, number)
    }

    /// Resolve by comparison index + number directly.
    pub fn resolve_index(
        &mut self,
        proc: &ProcessHandle,
        comparison_idx: u32,
        number: u32,
    ) -> Option<String> {
        let block_idx = comparison_idx >> 16;
        let offset = (comparison_idx & 0xFFFF) as usize;

        let block_data = self.cache.get_or_read(proc, &self.block_ptrs, block_idx)?;
        let byte_offset = offset * self.stride;
        let hdr_pos = byte_offset + self.header_off;
        if hdr_pos + 2 > block_data.len() {
            return None;
        }

        let header = u16::from_le_bytes([block_data[hdr_pos], block_data[hdr_pos + 1]]);
        let is_wide = (header & 1) != 0;
        let len = (header >> self.len_shift) as usize;

        if len == 0 || len > MAX_NAME_LEN {
            return None;
        }

        let str_start = hdr_pos + 2;
        let str_bytes = if is_wide { len * 2 } else { len };
        if str_start + str_bytes > block_data.len() {
            return None;
        }

        let name = if is_wide {
            let chars: Vec<u16> = block_data[str_start..str_start + str_bytes]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&chars)
        } else {
            String::from_utf8_lossy(&block_data[str_start..str_start + str_bytes]).into_owned()
        };

        if number > 0 {
            Some(format!("{}_{}", name, number - 1))
        } else {
            Some(name)
        }
    }

    /// Validate the pool by checking well-known indices.
    pub fn validate(&mut self, proc: &ProcessHandle) -> bool {
        match self.resolve_index(proc, 0, 0) {
            Some(ref s) if s == "None" => {}
            other => {
                eprintln!("[!] FNamePool validation: index 0 = {:?}, expected \"None\"", other);
                return false;
            }
        }
        println!("[+] FNamePool validated: index 0 = \"None\"");

        for i in 1..=10 {
            if let Some(name) = self.resolve_index(proc, i, 0) {
                println!("    FName[{i}] = \"{name}\"");
            }
        }
        true
    }
}

/// Try to decode the first entry in a block as "None".
fn try_decode_none(data: &[u8], header_off: usize, len_shift: u32) -> bool {
    if header_off + 2 > data.len() {
        return false;
    }
    let header = u16::from_le_bytes([data[header_off], data[header_off + 1]]);
    let len = (header >> len_shift) as usize;
    if len != 4 {
        return false;
    }
    let str_start = header_off + 2;
    if str_start + 4 > data.len() {
        return false;
    }
    &data[str_start..str_start + 4] == b"None"
}

/// Build a list of candidate allocator base addresses to try.
fn build_candidates(proc: &ProcessHandle, gnames_raw: usize) -> Vec<(String, usize)> {
    let mut candidates = Vec::new();

    // 1. GNames IS the allocator directly (Blocks at gnames + 0x10)
    candidates.push(("direct (offset 0)".into(), gnames_raw));

    // 2. GNames is a pointer to the allocator — dereference it
    if let Some(deref) = proc.ptr(gnames_raw) {
        candidates.push(("dereferenced".into(), deref));
    }

    // 3. GNames points to FNamePool, allocator is at a fixed offset past hash shards.
    //    Common offsets seen in different games: 0x30, 0x40, etc.
    //    Scan in 8-byte steps up to FNAME_POOL_SCAN_RANGE to cover varying shard counts.
    for off in (0x8..=FNAME_POOL_SCAN_RANGE).step_by(8) {
        candidates.push((format!("FNamePool+{off:#X}"), gnames_raw + off));
    }

    // 4. Same scan but on the dereferenced pointer
    if let Some(deref) = proc.ptr(gnames_raw) {
        for off in (0x8..=FNAME_POOL_SCAN_RANGE).step_by(8) {
            candidates.push((format!("deref+{off:#X}"), deref + off));
        }
    }

    candidates
}

/// Read block pointers from the Blocks[] array.
fn read_block_ptrs(proc: &ProcessHandle, blocks_base: usize) -> Vec<usize> {
    let mut block_ptrs = Vec::new();
    for i in 0..FNAME_POOL_MAX_BLOCKS {
        let addr = blocks_base + i * 8;
        match proc.read::<u64>(addr) {
            Some(v) => block_ptrs.push(v as usize),
            None => break,
        }
        // Stop early once we hit consecutive nulls
        if i > 2 && block_ptrs[i] == 0 && block_ptrs[i - 1] == 0 {
            break;
        }
    }
    block_ptrs
}
