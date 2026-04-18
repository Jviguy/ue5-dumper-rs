use crate::mem::ProcessHandle;
use super::fname::FNamePool;
use super::objects::GObjects;
use super::offsets::*;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct ClassDump {
    pub name: String,
    pub full_name: String,
    pub parent: Option<String>,
    pub size: u32,
    pub properties: Vec<PropertyDump>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<FunctionDump>,
}

#[derive(Debug, Serialize)]
pub struct FunctionDump {
    pub name: String,
    pub full_name: String,
    pub flags: u32,
    pub native_func: u64,
    pub params: Vec<PropertyDump>,
}

#[derive(Debug, Serialize)]
pub struct PropertyDump {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
    pub offset: u32,
    pub size: u32,
    pub array_dim: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_type: Option<String>,
    /// For `BoolProperty` only: the single bit within the containing byte that
    /// this bool occupies, if it's a native bitfield (e.g. `uint8 bFoo : 1`).
    /// `None` for regular `bool` fields (whole byte).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_index: Option<u8>,
    /// For `BoolProperty` only: the raw `FieldMask`. `0xFF` means full byte
    /// (regular bool). A single bit set means bitfield.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_mask: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct EnumDump {
    pub name: String,
    pub full_name: String,
    pub variants: Vec<EnumVariant>,
}

#[derive(Debug, Serialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

/// Walk all classes/structs and dump their property layouts.
pub fn dump_classes(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    gobjects: &GObjects,
    filter: Option<&str>,
) -> Vec<ClassDump> {
    // First pass: identify which objects are UClass or UScriptStruct instances
    // by checking if their class's name is "Class" or "ScriptStruct".
    let mut class_name_cache: HashMap<usize, String> = HashMap::new();
    let mut field_class_name_cache: HashMap<usize, String> = HashMap::new();

    let mut classes = Vec::new();

    for obj in &gobjects.objects {
        let class_name = get_cached_name(
            proc,
            names,
            &mut class_name_cache,
            obj.class_addr,
        );
        let class_name = match class_name {
            Some(n) => n,
            None => continue,
        };

        if class_name != "Class" && class_name != "ScriptStruct" {
            continue;
        }

        // This object is a UClass or UScriptStruct — read its layout
        let obj_name = match names.resolve_index(proc, obj.name_idx, obj.name_number) {
            Some(n) => n,
            None => continue,
        };

        // Apply filter if specified
        if let Some(pat) = filter {
            let full = gobjects.full_name(proc, names, obj.addr).unwrap_or_default();
            if !obj_name.contains(pat) && !full.contains(pat) {
                continue;
            }
        }

        let full_name = gobjects
            .full_name(proc, names, obj.addr)
            .unwrap_or_else(|| obj_name.clone());

        // Read SuperStruct
        let super_addr = proc.read::<u64>(obj.addr + USTRUCT_SUPER).unwrap_or(0) as usize;
        let parent = if super_addr != 0 {
            let idx = proc.read::<u32>(super_addr + UOBJECT_FNAME).unwrap_or(0);
            let num = proc.read::<u32>(super_addr + UOBJECT_FNAME + 4).unwrap_or(0);
            names.resolve_index(proc, idx, num)
        } else {
            None
        };

        // Read PropertiesSize
        let size = proc.read::<u32>(obj.addr + USTRUCT_PROPERTIES_SIZE).unwrap_or(0);

        // Walk ChildProperties linked list (FField chain)
        let properties = walk_properties(
            proc,
            names,
            gobjects,
            &mut field_class_name_cache,
            obj.addr,
        );

        // Walk Children linked list (UField chain → UFunctions)
        let functions = walk_functions(
            proc,
            names,
            gobjects,
            &mut class_name_cache,
            &mut field_class_name_cache,
            obj.addr,
        );

        classes.push(ClassDump {
            name: obj_name,
            full_name,
            parent,
            size,
            properties,
            functions,
        });
    }

    let total_funcs: usize = classes.iter().map(|c| c.functions.len()).sum();
    println!("[+] Dumped {} classes/structs ({} functions)", classes.len(), total_funcs);
    classes
}

/// Walk all UEnum instances in GObjects and dump their variant name/value pairs.
pub fn dump_enums(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    gobjects: &GObjects,
    filter: Option<&str>,
) -> Vec<EnumDump> {
    let mut class_name_cache: HashMap<usize, String> = HashMap::new();
    let mut enums = Vec::new();

    for obj in &gobjects.objects {
        let class_name = get_cached_name(
            proc,
            names,
            &mut class_name_cache,
            obj.class_addr,
        );
        if class_name.as_deref() != Some("Enum") {
            continue;
        }

        let enum_name = match names.resolve_index(proc, obj.name_idx, obj.name_number) {
            Some(n) => n,
            None => continue,
        };

        if let Some(pat) = filter {
            let full = gobjects.full_name(proc, names, obj.addr).unwrap_or_default();
            if !enum_name.contains(pat) && !full.contains(pat) {
                continue;
            }
        }

        let full_name = gobjects
            .full_name(proc, names, obj.addr)
            .unwrap_or_else(|| enum_name.clone());

        let variants = read_enum_variants(proc, names, obj.addr);
        if variants.is_empty() {
            continue;
        }

        enums.push(EnumDump {
            name: enum_name,
            full_name,
            variants,
        });
    }

    println!("[+] Dumped {} enums", enums.len());
    enums
}

/// Read `TArray<TPair<FName, int64>> Names` from a UEnum.
fn read_enum_variants(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    enum_addr: usize,
) -> Vec<EnumVariant> {
    let names_addr = enum_addr + UENUM_NAMES;
    let data_ptr = match proc.ptr(names_addr) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let len = proc.read::<i32>(names_addr + 8).unwrap_or(0);
    if len <= 0 || (len as usize) > 1024 {
        return Vec::new();
    }

    let buf_size = (len as usize) * UENUM_VARIANT_STRIDE;
    let buf = match proc.read_bytes(data_ptr, buf_size) {
        Some(b) => b,
        None => return Vec::new(),
    };

    let mut out = Vec::with_capacity(len as usize);
    for i in 0..len as usize {
        let base = i * UENUM_VARIANT_STRIDE;
        if base + UENUM_VARIANT_STRIDE > buf.len() {
            break;
        }
        let comp_idx = u32::from_le_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]]);
        let number = u32::from_le_bytes([buf[base + 4], buf[base + 5], buf[base + 6], buf[base + 7]]);
        let value = i64::from_le_bytes([
            buf[base + 8], buf[base + 9], buf[base + 10], buf[base + 11],
            buf[base + 12], buf[base + 13], buf[base + 14], buf[base + 15],
        ]);
        let name = names.resolve_index(proc, comp_idx, number).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(EnumVariant { name, value });
    }
    out
}

/// Walk the ChildProperties linked list of a UStruct.
fn walk_properties(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    gobjects: &GObjects,
    field_class_cache: &mut HashMap<usize, String>,
    struct_addr: usize,
) -> Vec<PropertyDump> {
    let mut props = Vec::new();
    let mut field_addr = match proc.read::<u64>(struct_addr + USTRUCT_CHILD_PROPERTIES) {
        Some(v) if v != 0 => v as usize,
        _ => return props,
    };

    let mut depth = 0;
    while field_addr != 0 && depth < MAX_FIELD_DEPTH {
        depth += 1;

        // Read FField::Name
        let prop_name = names.resolve(proc, field_addr + FFIELD_NAME).unwrap_or_default();

        // Read FField::ClassPrivate to get the type name
        let class_private = proc.read::<u64>(field_addr + FFIELD_CLASS_PRIVATE).unwrap_or(0) as usize;
        let type_name = if class_private != 0 {
            get_cached_ffield_class_name(proc, names, field_class_cache, class_private)
                .unwrap_or_else(|| "Unknown".into())
        } else {
            "Unknown".into()
        };

        // Read FProperty fields
        let array_dim = proc.read::<u32>(field_addr + FPROPERTY_ARRAY_DIM).unwrap_or(1);
        let element_size = proc.read::<u32>(field_addr + FPROPERTY_ELEMENT_SIZE).unwrap_or(0);
        let offset = proc.read::<u32>(field_addr + FPROPERTY_OFFSET).unwrap_or(0);

        // Try to resolve inner type info for container/struct properties
        let inner_type = resolve_inner_type(proc, names, gobjects, &type_name, field_addr);

        // BoolProperty gets extra FieldMask info for native bitfield detection.
        let (bit_index, field_mask) = if type_name == "BoolProperty" {
            let mask = proc.read::<u8>(field_addr + FBOOL_PROP_FIELD_MASK).unwrap_or(0xFF);
            // FieldMask = 0xFF → regular bool; single bit set → bitfield.
            let bit = if mask != 0 && mask != 0xFF && (mask & mask.wrapping_sub(1)) == 0 {
                Some(mask.trailing_zeros() as u8)
            } else {
                None
            };
            (bit, Some(mask))
        } else {
            (None, None)
        };

        props.push(PropertyDump {
            name: prop_name,
            prop_type: type_name,
            offset,
            size: element_size,
            array_dim,
            inner_type,
            bit_index,
            field_mask,
        });

        // Follow Next pointer
        field_addr = match proc.read::<u64>(field_addr + FFIELD_NEXT) {
            Some(v) if v != 0 => v as usize,
            _ => 0,
        };
    }

    props
}

/// Walk the Children linked list of a UStruct (UField chain → UFunctions).
fn walk_functions(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    gobjects: &GObjects,
    class_name_cache: &mut HashMap<usize, String>,
    field_class_cache: &mut HashMap<usize, String>,
    struct_addr: usize,
) -> Vec<FunctionDump> {
    let mut funcs = Vec::new();
    let mut ufield_addr = match proc.read::<u64>(struct_addr + USTRUCT_CHILDREN) {
        Some(v) if v != 0 => v as usize,
        _ => return funcs,
    };

    let mut depth = 0;
    while ufield_addr != 0 && depth < MAX_FIELD_DEPTH {
        depth += 1;

        // Check if this UField is a UFunction by reading its class name
        let class_addr = proc.read::<u64>(ufield_addr + UOBJECT_CLASS).unwrap_or(0) as usize;
        let class_name = get_cached_name(proc, names, class_name_cache, class_addr);

        if class_name.as_deref() == Some("Function") {
            // Read function name
            let func_name = {
                let idx = proc.read::<u32>(ufield_addr + UOBJECT_FNAME).unwrap_or(0);
                let num = proc.read::<u32>(ufield_addr + UOBJECT_FNAME + 4).unwrap_or(0);
                names.resolve_index(proc, idx, num).unwrap_or_default()
            };

            let full_name = gobjects
                .full_name(proc, names, ufield_addr)
                .unwrap_or_else(|| func_name.clone());

            // Read FunctionFlags
            let flags = proc.read::<u32>(ufield_addr + UFUNCTION_FLAGS).unwrap_or(0);

            // Read native function pointer
            let native_func = proc.read::<u64>(ufield_addr + UFUNCTION_FUNC).unwrap_or(0);

            // Walk the function's own ChildProperties for parameters
            let params = walk_properties(
                proc,
                names,
                gobjects,
                field_class_cache,
                ufield_addr,
            );

            funcs.push(FunctionDump {
                name: func_name,
                full_name,
                flags,
                native_func,
                params,
            });
        }

        // Follow UField::Next
        ufield_addr = match proc.read::<u64>(ufield_addr + UFIELD_NEXT) {
            Some(v) if v != 0 => v as usize,
            _ => 0,
        };
    }

    funcs
}

/// Resolve inner type info for known property subtypes.
fn resolve_inner_type(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    _gobjects: &GObjects,
    type_name: &str,
    field_addr: usize,
) -> Option<String> {
    match type_name {
        "StructProperty" => {
            // FStructProperty::Struct -> UScriptStruct*, read its name
            let inner = proc.read::<u64>(field_addr + FSTRUCT_PROP_STRUCT).unwrap_or(0) as usize;
            if inner != 0 {
                return read_uobject_name(proc, names, inner);
            }
            None
        }
        "ObjectProperty" | "ObjectPtrProperty" | "SoftObjectProperty" | "WeakObjectProperty" | "LazyObjectProperty" => {
            let inner = proc.read::<u64>(field_addr + FOBJECT_PROP_CLASS).unwrap_or(0) as usize;
            if inner != 0 {
                return read_uobject_name(proc, names, inner);
            }
            None
        }
        "ArrayProperty" => {
            let inner = proc.read::<u64>(field_addr + FARRAY_PROP_INNER).unwrap_or(0) as usize;
            if inner != 0 {
                // Inner is an FProperty — read its FFieldClass name
                let cls = proc.read::<u64>(inner + FFIELD_CLASS_PRIVATE).unwrap_or(0) as usize;
                if cls != 0 {
                    return read_fname_at(proc, names, cls + FFIELD_CLASS_NAME);
                }
            }
            None
        }
        "MapProperty" => {
            let key = proc.read::<u64>(field_addr + FMAP_PROP_KEY).unwrap_or(0) as usize;
            let val = proc.read::<u64>(field_addr + FMAP_PROP_VALUE).unwrap_or(0) as usize;
            let key_name = if key != 0 {
                let cls = proc.read::<u64>(key + FFIELD_CLASS_PRIVATE).unwrap_or(0) as usize;
                if cls != 0 { read_fname_at(proc, names, cls + FFIELD_CLASS_NAME) } else { None }
            } else {
                None
            };
            let val_name = if val != 0 {
                let cls = proc.read::<u64>(val + FFIELD_CLASS_PRIVATE).unwrap_or(0) as usize;
                if cls != 0 { read_fname_at(proc, names, cls + FFIELD_CLASS_NAME) } else { None }
            } else {
                None
            };
            Some(format!(
                "{} -> {}",
                key_name.unwrap_or_else(|| "?".into()),
                val_name.unwrap_or_else(|| "?".into())
            ))
        }
        "SetProperty" => {
            let inner = proc.read::<u64>(field_addr + FSET_PROP_ELEMENT).unwrap_or(0) as usize;
            if inner != 0 {
                let cls = proc.read::<u64>(inner + FFIELD_CLASS_PRIVATE).unwrap_or(0) as usize;
                if cls != 0 {
                    return read_fname_at(proc, names, cls + FFIELD_CLASS_NAME);
                }
            }
            None
        }
        "EnumProperty" => {
            let uenum = proc.read::<u64>(field_addr + FENUM_PROP_ENUM).unwrap_or(0) as usize;
            if uenum != 0 {
                return read_uobject_name(proc, names, uenum);
            }
            None
        }
        _ => None,
    }
}

/// Read a UObject's FName (Name field).
fn read_uobject_name(proc: &ProcessHandle, names: &mut FNamePool, addr: usize) -> Option<String> {
    let idx = proc.read::<u32>(addr + UOBJECT_FNAME)?;
    let num = proc.read::<u32>(addr + UOBJECT_FNAME + 4)?;
    names.resolve_index(proc, idx, num)
}

/// Read an FName at an arbitrary address.
fn read_fname_at(proc: &ProcessHandle, names: &mut FNamePool, addr: usize) -> Option<String> {
    names.resolve(proc, addr)
}

/// Cache helper: resolve the FName of a UObject (used for class lookups).
fn get_cached_name(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    cache: &mut HashMap<usize, String>,
    addr: usize,
) -> Option<String> {
    if addr == 0 {
        return None;
    }
    if let Some(cached) = cache.get(&addr) {
        return Some(cached.clone());
    }
    let name = read_uobject_name(proc, names, addr)?;
    cache.insert(addr, name.clone());
    Some(name)
}

/// Cache helper for FFieldClass name resolution.
fn get_cached_ffield_class_name(
    proc: &ProcessHandle,
    names: &mut FNamePool,
    cache: &mut HashMap<usize, String>,
    addr: usize,
) -> Option<String> {
    if let Some(cached) = cache.get(&addr) {
        return Some(cached.clone());
    }
    let name = read_fname_at(proc, names, addr + FFIELD_CLASS_NAME)?;
    cache.insert(addr, name.clone());
    Some(name)
}
