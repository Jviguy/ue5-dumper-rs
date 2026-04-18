use crate::mem::ProcessHandle;
use crate::ue::fname::FNamePool;
use crate::ue::offsets::{MAX_USERSPACE, MIN_VALID_PTR};

/// Results from scanning the game binary for global addresses.
pub struct ScanResults {
    /// Absolute address of FNameEntryAllocator.
    pub gnames: usize,
    /// Absolute address of FUObjectArray.
    pub gobjects: usize,
    /// Absolute address of GWorld pointer.
    pub gworld: usize,
}

impl ScanResults {
    /// Return offsets relative to the image base.
    pub fn offsets(&self, base: usize) -> (usize, usize, usize) {
        (self.gnames - base, self.gobjects - base, self.gworld - base)
    }
}

/// Scan the game binary for GNames, GObjects, and GWorld.
///
/// Two-phase approach:
/// 1. Find GNames (validated by decoding "None") and init FNamePool
/// 2. Use FNamePool to validate GObjects and GWorld candidates by resolving names
pub fn scan(proc: &ProcessHandle) -> Option<ScanResults> {
    let (text_start, text_size) = find_text_section(proc)?;
    println!(
        "[*] .text section: {text_start:#X} size {:#X} ({:.1} MB)",
        text_size,
        text_size as f64 / (1024.0 * 1024.0)
    );

    // Phase 1: Find GNames (self-validating via "None" decode)
    let gnames = scan_gnames(proc, text_start, text_size)?;
    println!("[+] GNames: {gnames:#X} (base + {:#X})", gnames - proc.base);

    // Init FNamePool for name-based validation of the other globals
    let mut names = match FNamePool::with_addr(proc, gnames) {
        Some(n) => n,
        None => {
            eprintln!("[!] Failed to init FNamePool from scanned GNames");
            return None;
        }
    };
    if !names.validate(proc) {
        eprintln!("[!] FNamePool from scanned GNames failed validation");
        return None;
    }

    // Phase 2: Find GObjects (validated by resolving object names)
    let gobjects = scan_gobjects(proc, &mut names, text_start, text_size)?;
    println!("[+] GObjects: {gobjects:#X} (base + {:#X})", gobjects - proc.base);

    // Phase 3: Find GWorld (validated by checking class name is "World")
    let gworld = scan_gworld(proc, &mut names, text_start, text_size)?;
    println!("[+] GWorld: {gworld:#X} (base + {:#X})", gworld - proc.base);

    Some(ScanResults {
        gnames,
        gobjects,
        gworld,
    })
}

// ── PE Header Parsing ───────────────────────────────────────────────

/// Parse the PE header to find the .text section's virtual address and size.
fn find_text_section(proc: &ProcessHandle) -> Option<(usize, usize)> {
    let base = proc.base;

    let e_lfanew = proc.read::<u32>(base + 0x3C)? as usize;
    let pe_sig = proc.read::<u32>(base + e_lfanew)?;
    if pe_sig != 0x00004550 {
        eprintln!("[!] Invalid PE signature: {pe_sig:#X}");
        return None;
    }

    let pe_header = base + e_lfanew;
    let num_sections = proc.read::<u16>(pe_header + 0x06)? as usize;
    let optional_header_size = proc.read::<u16>(pe_header + 0x14)? as usize;
    let sections_start = pe_header + 0x18 + optional_header_size;

    for i in 0..num_sections {
        let sec = sections_start + i * 40;
        let name_bytes = proc.read_bytes(sec, 8)?;
        let name = std::str::from_utf8(&name_bytes)
            .unwrap_or("")
            .trim_end_matches('\0');

        if name == ".text" {
            let virtual_size = proc.read::<u32>(sec + 0x08)? as usize;
            let virtual_addr = proc.read::<u32>(sec + 0x0C)? as usize;
            return Some((base + virtual_addr, virtual_size));
        }
    }

    eprintln!("[!] .text section not found");
    None
}

// ── Pattern Matching Engine ─────────────────────────────────────────

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Scan a memory region for a byte pattern with `None` as wildcard.
fn scan_pattern(
    proc: &ProcessHandle,
    start: usize,
    size: usize,
    pattern: &[Option<u8>],
) -> Vec<usize> {
    let mut results = Vec::new();
    let pat_len = pattern.len();
    if pat_len == 0 || size < pat_len {
        return results;
    }

    let mut offset = 0;
    while offset < size {
        let read_len = (size - offset).min(CHUNK_SIZE);

        let data = match proc.read_bytes(start + offset, read_len) {
            Some(d) => d,
            None => {
                offset += CHUNK_SIZE.saturating_sub(pat_len);
                continue;
            }
        };

        let scan_end = data.len().saturating_sub(pat_len - 1);

        for i in 0..scan_end {
            let mut matched = true;
            for (j, &pat_byte) in pattern.iter().enumerate() {
                if let Some(expected) = pat_byte {
                    if data[i + j] != expected {
                        matched = false;
                        break;
                    }
                }
            }
            if matched {
                results.push(start + offset + i);
            }
        }

        if CHUNK_SIZE <= pat_len {
            break;
        }
        // Overlap by pattern length to catch boundary matches
        offset += CHUNK_SIZE - pat_len;
    }

    results
}

/// Resolve a RIP-relative address.
fn resolve_rip_relative(proc: &ProcessHandle, match_addr: usize, instr_len: usize, disp_offset: usize) -> Option<usize> {
    let disp = proc.read::<i32>(match_addr + disp_offset)?;
    let target = (match_addr + instr_len) as i64 + disp as i64;
    if target <= 0 || target as usize > MAX_USERSPACE {
        return None;
    }
    Some(target as usize)
}

/// Collect all RIP-relative targets from LEA/MOV patterns.
fn collect_rip_targets(
    proc: &ProcessHandle,
    text_start: usize,
    text_size: usize,
    patterns: &[&[Option<u8>]],
) -> Vec<usize> {
    let mut targets = Vec::new();
    for &pattern in patterns {
        let matches = scan_pattern(proc, text_start, text_size, pattern);
        for &addr in &matches {
            if let Some(target) = resolve_rip_relative(proc, addr, 7, 3) {
                targets.push(target);
            }
        }
    }
    targets
}

// ── Safe pointer arithmetic helpers ─────────────────────────────────

fn safe_ptr(proc: &ProcessHandle, addr: usize) -> Option<usize> {
    if addr > MAX_USERSPACE { return None; }
    match proc.ptr(addr) {
        Some(p) if p <= MAX_USERSPACE => Some(p),
        _ => None,
    }
}

fn safe_ptr_at(proc: &ProcessHandle, base: usize, offset: usize) -> Option<usize> {
    safe_ptr(proc, base.checked_add(offset)?)
}

fn safe_read_u32(proc: &ProcessHandle, base: usize, offset: usize) -> Option<u32> {
    let addr = base.checked_add(offset)?;
    if addr > MAX_USERSPACE { return None; }
    proc.read::<u32>(addr)
}

// ── GNames Scanner ──────────────────────────────────────────────────

fn scan_gnames(proc: &ProcessHandle, text_start: usize, text_size: usize) -> Option<usize> {
    let lea_rcx: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x0D), None, None, None, None];

    println!("[*] Scanning for GNames...");
    let targets = collect_rip_targets(proc, text_start, text_size, &[lea_rcx]);
    println!("[*] Found {} LEA rcx candidates", targets.len());

    for target in targets {
        if validate_gnames(proc, target) {
            return Some(target);
        }
    }

    eprintln!("[!] GNames not found");
    None
}

/// Validate by checking if Block[0] entry 0 decodes to "None".
fn validate_gnames(proc: &ProcessHandle, addr: usize) -> bool {
    let block0 = match safe_ptr_at(proc, addr, 0x10) {
        Some(p) if p > MIN_VALID_PTR => p,
        _ => return false,
    };

    let data = match proc.read_bytes(block0, 16) {
        Some(d) => d,
        None => return false,
    };

    // Case-preserving: 4-byte ComparisonId prefix, header at +4, len = header >> 1
    if data.len() >= 10 {
        let header = u16::from_le_bytes([data[4], data[5]]);
        let len = (header >> 1) as usize;
        if len == 4 && &data[6..10] == b"None" {
            return true;
        }
    }

    // Shipping: header at +0, len = header >> 6
    if data.len() >= 6 {
        let header = u16::from_le_bytes([data[0], data[1]]);
        let len = (header >> 6) as usize;
        if len == 4 && &data[2..6] == b"None" {
            return true;
        }
    }

    false
}

// ── GObjects Scanner ────────────────────────────────────────────────

fn scan_gobjects(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    text_start: usize,
    text_size: usize,
) -> Option<usize> {
    let lea_rcx: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x0D), None, None, None, None];
    let lea_rdx: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x15), None, None, None, None];

    // Broad set of LEA/MOV patterns with RIP-relative addressing
    let lea_rax: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x05), None, None, None, None];
    let mov_rax: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x05), None, None, None, None];
    let mov_rcx: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x0D), None, None, None, None];
    let mov_rdx: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x15), None, None, None, None];
    // REX.W LEA r8-r15 variants (4C 8D XX)
    let lea_r8:  &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x05), None, None, None, None];
    let lea_r9:  &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x0D), None, None, None, None];
    // MOV r8-r15 variants (4C 8B XX)
    let mov_r8:  &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x05), None, None, None, None];
    let mov_r9:  &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x0D), None, None, None, None];

    println!("[*] Scanning for GObjects...");
    let targets = collect_rip_targets(proc, text_start, text_size, &[
        lea_rcx, lea_rdx, lea_rax,
        mov_rax, mov_rcx, mov_rdx,
        lea_r8, lea_r9, mov_r8, mov_r9,
    ]);
    println!("[*] Found {} LEA/MOV candidates for GObjects", targets.len());

    for target in targets {
        if validate_gobjects(proc, names, target) {
            return Some(target);
        }
    }

    eprintln!("[!] GObjects not found");
    None
}

/// Validate by checking element count, chunk structure, and resolving class names.
fn validate_gobjects(proc: &ProcessHandle, names: &mut FNamePool, addr: usize) -> bool {
    use crate::ue::offsets::*;

    // NumElements at +0x14 — real UE5 games have plenty of objects
    let num_elements = match safe_read_u32(proc, addr, UOBJECT_ARRAY_NUM_ELEMENTS) {
        Some(n) if (n as usize) >= MIN_OBJECTS && (n as usize) < MAX_OBJECTS => n as usize,
        _ => return false,
    };

    // Objects chunk array pointer at +0x00
    let chunks_ptr = match safe_ptr_at(proc, addr, UOBJECT_ARRAY_OBJECTS) {
        Some(p) if p > MIN_VALID_PTR => p,
        _ => return false,
    };

    // First chunk pointer
    let chunk0 = match safe_ptr(proc, chunks_ptr) {
        Some(p) if p > MIN_VALID_PTR => p,
        _ => return false,
    };

    // Validate objects by resolving their *class* names.
    // Real GObjects: early objects are "Package", "Class", "Function", etc.
    // We require at least some objects whose class name is a known UE5 core class.
    let known_classes = ["Class", "Package", "Function", "ScriptStruct", "Enum"];
    let mut found_known_class = false;
    let mut valid_names = 0;

    for i in 0..20usize {
        let item_addr = match chunk0.checked_add(i * FUOBJECT_ITEM_SIZE) {
            Some(a) if a <= MAX_USERSPACE => a,
            _ => continue,
        };
        let obj_ptr = match safe_ptr(proc, item_addr) {
            Some(p) if p > MIN_VALID_PTR => p,
            _ => continue,
        };

        // Resolve the object's class name
        let class_ptr = match safe_ptr_at(proc, obj_ptr, UOBJECT_CLASS) {
            Some(p) if p > MIN_VALID_PTR => p,
            _ => continue,
        };
        let class_name_idx = match safe_read_u32(proc, class_ptr, UOBJECT_FNAME) {
            Some(idx) if idx < MAX_NAME_INDEX => idx,
            _ => continue,
        };

        if let Some(class_name) = names.resolve_index(proc, class_name_idx, 0) {
            if class_name.is_ascii() && class_name.len() >= 2 {
                valid_names += 1;
                if known_classes.contains(&class_name.as_str()) {
                    found_known_class = true;
                }
            }
        }
    }

    // Must find at least one known core class and multiple valid names
    if !found_known_class || valid_names < 5 {
        return false;
    }

    let _ = num_elements;
    true
}

// ── GWorld Scanner ──────────────────────────────────────────────────

fn scan_gworld(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    text_start: usize,
    text_size: usize,
) -> Option<usize> {
    // MOV [rip+disp32], rax/rdi — store patterns
    let mov_rax: &[Option<u8>] = &[Some(0x48), Some(0x89), Some(0x05), None, None, None, None];
    let mov_rdi: &[Option<u8>] = &[Some(0x48), Some(0x89), Some(0x3D), None, None, None, None];

    println!("[*] Scanning for GWorld...");
    let targets = collect_rip_targets(proc, text_start, text_size, &[mov_rax, mov_rdi]);
    println!("[*] Found {} MOV store candidates", targets.len());

    for target in targets {
        if validate_gworld(proc, names, target) {
            return Some(target);
        }
    }

    eprintln!("[!] GWorld not found");
    None
}

/// Validate by dereferencing and checking the class name resolves to "World".
fn validate_gworld(proc: &ProcessHandle, names: &mut FNamePool, addr: usize) -> bool {
    use crate::ue::offsets::*;

    // GWorld is a pointer-to-pointer: *addr = UWorld*
    let uworld = match safe_ptr(proc, addr) {
        Some(p) if p > MIN_VALID_PTR => p,
        _ => return false,
    };

    // UWorld.Class
    let class_addr = match safe_ptr_at(proc, uworld, UOBJECT_CLASS) {
        Some(p) if p > MIN_VALID_PTR => p,
        _ => return false,
    };

    // Resolve the class's FName — must be "World"
    let name_idx = match safe_read_u32(proc, class_addr, UOBJECT_FNAME) {
        Some(idx) => idx,
        None => return false,
    };

    match names.resolve_index(proc, name_idx, 0) {
        Some(ref name) if name == "World" => true,
        _ => false,
    }
}

