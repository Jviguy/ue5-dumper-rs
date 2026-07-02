use crate::mem::ProcessHandle;
use crate::scanner::EngineLayout;
use super::offsets::*;
use super::fname::FNamePool;

/// A resolved UObject reference.
pub struct UObjectRef {
    pub addr: usize,
    pub class_addr: usize,
    pub name_idx: u32,
    pub name_number: u32,
    pub outer_addr: usize,
}

/// Reads and caches the GObjects array.
pub struct GObjects {
    /// All non-null UObject addresses with their basic fields.
    pub objects: Vec<UObjectRef>,
}

impl GObjects {
    /// Read the entire GObjects array using an explicit FUObjectArray address.
    ///
    /// The scanner ([`crate::scanner::scan`]) produces this address.
    pub fn with_addr(proc: &ProcessHandle, gobjects_addr: usize, layout: EngineLayout) -> Option<Self> {
        let chunks_ptr = proc.ptr(gobjects_addr + UOBJECT_ARRAY_OBJECTS)?;
        let num_elements = proc.read::<i32>(gobjects_addr + UOBJECT_ARRAY_NUM_ELEMENTS)? as usize;

        if num_elements == 0 || num_elements > MAX_OBJECTS {
            eprintln!("[!] GObjects: suspicious NumElements = {num_elements}");
            return None;
        }

        let item_size = layout.fuobject_item_size;
        let num_chunks = (num_elements + OBJECTS_PER_CHUNK - 1) / OBJECTS_PER_CHUNK;
        println!("[*] GObjects: {num_elements} elements in {num_chunks} chunks (item stride {item_size:#X})");

        // Read chunk pointer array
        let chunk_ptrs_bytes = proc.read_bytes(chunks_ptr, num_chunks * 8)?;
        let chunk_ptrs: Vec<usize> = chunk_ptrs_bytes
            .chunks_exact(8)
            .map(read_u64_le)
            .map(|v| v as usize)
            .collect();

        let mut objects = Vec::with_capacity(num_elements);

        // Page-sized batches. ReadProcessMemory fails for the entire range if
        // any page in it is uncommitted, and shipping UE builds routinely leave
        // the tail of a chunk uncommitted. Reading in 4 KB slabs lets us skip
        // the holes instead of losing the whole chunk.
        const BATCH_BYTES: usize = 4096;
        let items_per_batch = BATCH_BYTES / item_size;

        for (chunk_idx, &chunk_ptr) in chunk_ptrs.iter().enumerate() {
            if chunk_ptr == 0 {
                continue;
            }

            let remaining = num_elements - chunk_idx * OBJECTS_PER_CHUNK;
            let count = remaining.min(OBJECTS_PER_CHUNK);

            let mut i = 0;
            while i < count {
                let batch_count = items_per_batch.min(count - i);
                let batch_size = batch_count * item_size;
                let batch_addr = chunk_ptr + i * item_size;

                let batch = match proc.read_bytes(batch_addr, batch_size) {
                    Some(d) => d,
                    None => {
                        // Unmapped slab — skip it and keep going. Chunks often
                        // have uncommitted tail pages beyond the live items.
                        i += batch_count;
                        continue;
                    }
                };

                for j in 0..batch_count {
                    let item_off = j * item_size + FUOBJECT_ITEM_OBJ;
                    if item_off + 8 > batch.len() {
                        break;
                    }
                    let obj_ptr = read_u64_le(&batch[item_off..item_off + 8]) as usize;
                    if obj_ptr == 0 {
                        continue;
                    }
                    if let Some(obj) = read_uobject_ref(proc, obj_ptr) {
                        objects.push(obj);
                    }
                }
                i += batch_count;
            }
        }

        println!("[+] GObjects: loaded {} valid objects", objects.len());
        Some(Self { objects })
    }

    /// Validate by printing the first few object names.
    pub fn validate(&self, proc: &ProcessHandle, names: &mut FNamePool) {
        println!("[*] First 20 objects:");
        for (i, obj) in self.objects.iter().take(20).enumerate() {
            let name = names
                .resolve_index(proc, obj.name_idx, obj.name_number)
                .unwrap_or_else(|| "???".into());
            let outer = if obj.outer_addr != 0 {
                format!(" (outer={:#X})", obj.outer_addr)
            } else {
                String::new()
            };
            println!("    [{i}] {name}{outer} @ {:#X}", obj.addr);
        }
    }

    /// Build the full path for a UObject: Outer.Outer.Name
    pub fn full_name(
        &self,
        proc: &ProcessHandle,
        names: &mut FNamePool,
        addr: usize,
    ) -> Option<String> {
        let mut parts = Vec::new();
        let mut current = addr;
        let mut depth = 0;
        while current != 0 && depth < MAX_OUTER_DEPTH {
            let name_idx = proc.read::<u32>(current + UOBJECT_FNAME)?;
            let name_num = proc.read::<u32>(current + UOBJECT_FNAME + 4)?;
            let name = names.resolve_index(proc, name_idx, name_num)?;
            parts.push(name);
            current = proc.read::<u64>(current + UOBJECT_OUTER).unwrap_or(0) as usize;
            depth += 1;
        }
        parts.reverse();
        Some(parts.join("."))
    }
}

/// Read 8 little-endian bytes as u64. Callers are responsible for passing a slice of exactly 8.
#[inline]
fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(arr)
}

fn read_uobject_ref(proc: &ProcessHandle, addr: usize) -> Option<UObjectRef> {
    let class_addr = proc.read::<u64>(addr + UOBJECT_CLASS)? as usize;
    let name_idx = proc.read::<u32>(addr + UOBJECT_FNAME)?;
    let name_number = proc.read::<u32>(addr + UOBJECT_FNAME + 4)?;
    let outer_addr = proc.read::<u64>(addr + UOBJECT_OUTER).unwrap_or(0) as usize;

    Some(UObjectRef {
        addr,
        class_addr,
        name_idx,
        name_number,
        outer_addr,
    })
}
