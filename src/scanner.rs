use crate::mem::ProcessHandle;
use crate::ue::fname::FNamePool;
use crate::ue::offsets::{MAX_USERSPACE, MIN_VALID_PTR};

/// Runtime-detected engine layout values that vary across UE5 versions.
#[derive(Debug, Clone, Copy)]
pub struct EngineLayout {
    /// FUObjectItem stride (0x18 on most builds, 0x20 on some aligned builds).
    pub fuobject_item_size: usize,
}

/// Results from scanning the game binary for global addresses.
pub struct ScanResults {
    /// Absolute address of FNameEntryAllocator.
    pub gnames: usize,
    /// Absolute address of FUObjectArray.
    pub gobjects: usize,
    /// Absolute address of GWorld pointer.
    pub gworld: usize,
    /// Detected engine layout (FUObjectItem stride, etc.).
    pub layout: EngineLayout,
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
    let (gobjects, layout) = scan_gobjects(proc, &mut names, text_start, text_size)?;
    println!("[+] GObjects: {gobjects:#X} (base + {:#X})", gobjects - proc.base);
    println!("[+] Detected layout: FUObjectItem stride = {:#X}", layout.fuobject_item_size);

    // Phase 3: Find GWorld (validated by checking class name is "World")
    let gworld = scan_gworld(proc, &mut names, text_start, text_size)?;
    println!("[+] GWorld: {gworld:#X} (base + {:#X})", gworld - proc.base);

    Some(ScanResults {
        gnames,
        gobjects,
        gworld,
        layout,
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
) -> Option<(usize, EngineLayout)> {
    // All 16 register targets for REX.W LEA / MOV with RIP-relative addressing.
    // Compilers routinely park globals in rsi/rdi/rbx (non-volatile) across calls,
    // so we MUST cover those — missing them is a common cause of scan failures.
    // ModR/M middle field: rax=000, rcx=001, rdx=010, rbx=011, rsp=100(invalid),
    // rbp=101, rsi=110, rdi=111 (shifted into bits 3..5 → 05/0D/15/1D/2D/35/3D).
    // REX.B=1 (4C prefix) extends to r8..r15 using the same encoding.
    let mut patterns: Vec<&[Option<u8>]> = Vec::new();
    // REX.W (48) LEA (8D) / MOV (8B) for rax..rdi (skip rsp which has SIB)
    const P_48_8D_05: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x05), None, None, None, None];
    const P_48_8D_0D: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x0D), None, None, None, None];
    const P_48_8D_15: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x15), None, None, None, None];
    const P_48_8D_1D: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x1D), None, None, None, None];
    const P_48_8D_2D: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x2D), None, None, None, None];
    const P_48_8D_35: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x35), None, None, None, None];
    const P_48_8D_3D: &[Option<u8>] = &[Some(0x48), Some(0x8D), Some(0x3D), None, None, None, None];
    const P_48_8B_05: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x05), None, None, None, None];
    const P_48_8B_0D: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x0D), None, None, None, None];
    const P_48_8B_15: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x15), None, None, None, None];
    const P_48_8B_1D: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x1D), None, None, None, None];
    const P_48_8B_2D: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x2D), None, None, None, None];
    const P_48_8B_35: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x35), None, None, None, None];
    const P_48_8B_3D: &[Option<u8>] = &[Some(0x48), Some(0x8B), Some(0x3D), None, None, None, None];
    // REX.WB (4C) for r8..r15 variants
    const P_4C_8D_05: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x05), None, None, None, None];
    const P_4C_8D_0D: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x0D), None, None, None, None];
    const P_4C_8D_15: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x15), None, None, None, None];
    const P_4C_8D_1D: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x1D), None, None, None, None];
    const P_4C_8D_2D: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x2D), None, None, None, None];
    const P_4C_8D_35: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x35), None, None, None, None];
    const P_4C_8D_3D: &[Option<u8>] = &[Some(0x4C), Some(0x8D), Some(0x3D), None, None, None, None];
    const P_4C_8B_05: &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x05), None, None, None, None];
    const P_4C_8B_0D: &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x0D), None, None, None, None];
    const P_4C_8B_15: &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x15), None, None, None, None];
    const P_4C_8B_1D: &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x1D), None, None, None, None];
    const P_4C_8B_2D: &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x2D), None, None, None, None];
    const P_4C_8B_35: &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x35), None, None, None, None];
    const P_4C_8B_3D: &[Option<u8>] = &[Some(0x4C), Some(0x8B), Some(0x3D), None, None, None, None];
    patterns.extend_from_slice(&[
        P_48_8D_05, P_48_8D_0D, P_48_8D_15, P_48_8D_1D, P_48_8D_2D, P_48_8D_35, P_48_8D_3D,
        P_48_8B_05, P_48_8B_0D, P_48_8B_15, P_48_8B_1D, P_48_8B_2D, P_48_8B_35, P_48_8B_3D,
        P_4C_8D_05, P_4C_8D_0D, P_4C_8D_15, P_4C_8D_1D, P_4C_8D_2D, P_4C_8D_35, P_4C_8D_3D,
        P_4C_8B_05, P_4C_8B_0D, P_4C_8B_15, P_4C_8B_1D, P_4C_8B_2D, P_4C_8B_35, P_4C_8B_3D,
    ]);

    println!("[*] Scanning for GObjects...");
    let targets = collect_rip_targets(proc, text_start, text_size, &patterns);
    println!("[*] Found {} LEA/MOV candidates for GObjects", targets.len());

    let mut near_misses: Vec<NearMiss> = Vec::new();
    let mut seen_nm: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for target in targets {
        match validate_gobjects(proc, names, target) {
            Validation::Valid { effective_addr, stride } => {
                return Some((effective_addr, EngineLayout { fuobject_item_size: stride }));
            }
            Validation::NearMiss(nm) if seen_nm.insert(nm.chunk0) => {
                near_misses.push(nm);
            }
            _ => {}
        }
    }

    // Keep only the top near-misses, ranked by their best (unique, valid) score.
    near_misses.sort_by_key(|nm| {
        let best = nm.stride_results.iter().map(|(_, v, u, _, _)| (*u, *v)).max().unwrap_or((0, 0));
        std::cmp::Reverse(best)
    });
    near_misses.truncate(10);

    eprintln!("[!] GObjects not found");
    if !near_misses.is_empty() {
        eprintln!("[!] Top {} near-miss candidates (passed NumElements + chunk0 checks):", near_misses.len());
        for nm in &near_misses {
            eprintln!(
                "    lea_target={:#X} (+{:#X}) num={} chunks_ptr={:#X} chunk0={:#X}",
                nm.addr, nm.base_off, nm.num_elements, nm.chunks_ptr, nm.chunk0,
            );
            for (stride, names_hits, unique, known_hit, samples) in &nm.stride_results {
                eprintln!(
                    "      stride={stride:#X}: {names_hits}/200 valid, {unique} unique classes, known: {known_hit}, samples: {samples:?}"
                );
            }
            if let Some(ref bytes) = nm.chunk0_preview {
                let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                eprintln!("      chunk0[0..0x40]: {hex}");
            }
        }
    }
    None
}

enum Validation {
    Valid { effective_addr: usize, stride: usize },
    NearMiss(NearMiss),
    Reject,
}

struct NearMiss {
    addr: usize,
    base_off: usize,
    num_elements: usize,
    chunks_ptr: usize,
    chunk0: usize,
    /// (stride, valid_name_count, unique_class_count, found_known_class, sample_names)
    stride_results: Vec<(usize, usize, usize, bool, Vec<String>)>,
    chunk0_preview: Option<Vec<u8>>,
}

/// Probe the LEA target at several base offsets (the LEA may point to
/// FUObjectArray itself or to its ObjObjects member at +0x10) and multiple
/// FUObjectItem strides. Returns the effective address + stride that validate.
fn validate_gobjects(proc: &ProcessHandle, names: &mut FNamePool, addr: usize) -> Validation {
    // FUObjectArray outer: ObjObjects member lives at +0x10 in UE5.x.
    // TUObjectArray inner: dereference directly.
    // Try both; the scanner gets hits for LEAs pointing to either.
    let base_offsets = [0x0usize, 0x10];
    let mut best_near: Option<NearMiss> = None;

    for &base_off in &base_offsets {
        let root = match addr.checked_add(base_off) {
            Some(a) if a <= MAX_USERSPACE => a,
            _ => continue,
        };
        match validate_gobjects_at(proc, names, root, addr, base_off) {
            Validation::Valid { effective_addr, stride } => {
                return Validation::Valid { effective_addr, stride };
            }
            Validation::NearMiss(nm) => {
                // Prefer the near-miss with the most promising stride result
                let score = |nm: &NearMiss| -> usize {
                    nm.stride_results.iter().map(|(_, v, _, _, _)| *v).max().unwrap_or(0)
                };
                if best_near.as_ref().map_or(true, |existing| score(&nm) > score(existing)) {
                    best_near = Some(nm);
                }
            }
            Validation::Reject => {}
        }
    }

    match best_near {
        Some(nm) => Validation::NearMiss(nm),
        None => Validation::Reject,
    }
}

fn validate_gobjects_at(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    root: usize,
    original: usize,
    base_off: usize,
) -> Validation {
    use crate::ue::offsets::*;

    let num_elements = match safe_read_u32(proc, root, UOBJECT_ARRAY_NUM_ELEMENTS) {
        Some(n) if (n as usize) >= MIN_OBJECTS && (n as usize) < MAX_OBJECTS => n as usize,
        _ => return Validation::Reject,
    };

    let chunks_ptr = match safe_ptr_at(proc, root, UOBJECT_ARRAY_OBJECTS) {
        Some(p) if p > MIN_VALID_PTR => p,
        _ => return Validation::Reject,
    };

    // chunks_ptr must point to heap, not back into the image. On Windows the
    // PE lives in the 0x7FF6... (or similar 0x7FFx) range; heap allocations
    // have different high bits. If chunks_ptr shares the image's high 32 bits
    // we're almost certainly misreading a pointer stored in .data as the
    // FUObjectArray fields.
    if (chunks_ptr >> 32) == (proc.base >> 32) {
        return Validation::Reject;
    }

    let chunk0 = match safe_ptr(proc, chunks_ptr) {
        Some(p) if p > MIN_VALID_PTR => p,
        _ => return Validation::Reject,
    };

    // Probe enough items to exercise real class diversity. Cyclic buffers
    // surface only a handful; genuine GObjects starts with Package/Class/
    // Function/ScriptStruct/... and adds more classes quickly.
    const PROBE_COUNT: usize = 200;
    let known_classes = ["Class", "Package", "Function", "ScriptStruct", "Enum"];
    let strides_to_try = [0x18usize, 0x20usize];
    let mut stride_results: Vec<(usize, usize, usize, bool, Vec<String>)> = Vec::with_capacity(strides_to_try.len());
    let mut best: Option<(usize, usize, usize, bool)> = None;

    for &stride in &strides_to_try {
        let mut found_known_class = false;
        let mut valid_names = 0;
        let mut unique: std::collections::HashSet<String> = std::collections::HashSet::new();

        for i in 0..PROBE_COUNT {
            let item_addr = match chunk0.checked_add(i * stride) {
                Some(a) if a <= MAX_USERSPACE => a,
                _ => continue,
            };
            let obj_ptr = match safe_ptr(proc, item_addr) {
                Some(p) if p > MIN_VALID_PTR => p,
                _ => continue,
            };
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
                    unique.insert(class_name);
                }
            }
        }

        // Capture up to 8 sample class names for diagnostic output.
        let mut samples: Vec<String> = unique.iter().cloned().collect();
        samples.sort();
        samples.truncate(8);
        stride_results.push((stride, valid_names, unique.len(), found_known_class, samples));

        if best.map(|(_, _, u, _)| unique.len() > u).unwrap_or(true) {
            best = Some((stride, valid_names, unique.len(), found_known_class));
        }
    }

    if let Some((stride, valid, unique, known)) = best {
        // Discriminator is density + presence of core classes, NOT class
        // diversity. The first 200 GObjects entries of a small UE5 title
        // are overwhelmingly UPackages + UClasses (type names "Package",
        // "Class", "Object"), so demanding 10+ unique classes rejects
        // legitimate hits. Cyclic/aliased false positives fail the density
        // check (typically ≤15% valid) while real GObjects hits near 100%.
        let density_ok = valid * 100 / PROBE_COUNT >= 75;
        if known && density_ok && unique >= 2 {
            if base_off != 0 {
                println!("    [+] GObjects resolved via outer FUObjectArray (LEA target {original:#X} + {base_off:#X}, stride {stride:#X}, {valid}/{PROBE_COUNT} valid, {unique} unique classes)");
            }
            return Validation::Valid { effective_addr: root, stride };
        }
    }

    let chunk0_preview = proc.read_bytes(chunk0, 0x40);
    Validation::NearMiss(NearMiss {
        addr: original,
        base_off,
        num_elements,
        chunks_ptr,
        chunk0,
        stride_results,
        chunk0_preview,
    })
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

