//! UE5 struct layout offsets.
//!
//! These describe the generic UE5 engine layout and are stable across games
//! built with the same engine variant (shipping/editor, case-preserving FName).
//! Per-game *global addresses* (GNames, GObjects, GWorld) are intentionally
//! NOT listed here — they are found at runtime by [`crate::scanner`].
//!
//! Some constants are published for documentation purposes even if not
//! currently consumed by the dumper itself — e.g. the full FBoolProperty
//! layout. Hence the module-level `allow(dead_code)`.

#![allow(dead_code)]

// ── Sanity limits ───────────────────────────────────────────────────

/// Max valid user-space address on x86_64 (48-bit canonical addressing).
pub const MAX_USERSPACE: usize = 0x0000_FFFF_FFFF_FFFF;

/// Smallest plausible pointer value (filters out null and small integers).
pub const MIN_VALID_PTR: usize = 0x10000;

/// Cap on GObjects count — real UE5 games are typically 100K–5M.
pub const MAX_OBJECTS: usize = 10_000_000;

/// Minimum GObjects count a real game must have (used to validate scan hits).
///
/// Small shipping UE5 titles with stripped content can run ~30K objects;
/// the pre-engine load floor is typically ~20K. Tune on a per-title basis
/// if the scanner rejects a legitimate hit.
pub const MIN_OBJECTS: usize = 20_000;

/// Upper bound for FField linked-list walks (guards against cycles).
pub const MAX_FIELD_DEPTH: usize = 4096;

/// Upper bound for Outer-chain walks when building full object names.
pub const MAX_OUTER_DEPTH: usize = 32;

/// Reject FName strings longer than this during decode.
pub const MAX_NAME_LEN: usize = 1024;

/// Reject FName indices larger than this when validating scan candidates.
pub const MAX_NAME_INDEX: u32 = 0x0400_0000;

// ── FNamePool / FNameEntry ───────────────────────────────────────────

/// Max number of 64K-entry blocks we will try to enumerate.
pub const FNAME_POOL_MAX_BLOCKS: usize = 8192;

/// Max entries per block (header-defined 16-bit offset unit).
pub const FNAME_POOL_OFFSET_UNITS: usize = 0xFFFF;

/// Upper bound (in bytes) when brute-scanning an FNamePool for its allocator.
pub const FNAME_POOL_SCAN_RANGE: usize = 0x10000;

// ── FUObjectArray / FUObjectItem ─────────────────────────────────────

pub const UOBJECT_ARRAY_OBJECTS: usize = 0x00;
pub const UOBJECT_ARRAY_NUM_ELEMENTS: usize = 0x14;
pub const OBJECTS_PER_CHUNK: usize = 65536;
pub const FUOBJECT_ITEM_SIZE: usize = 0x20;
pub const FUOBJECT_ITEM_OBJ: usize = 0x00;

// ── UObject layout (non-case-preserving shipping UE5) ──────────────
// UObjectBase: vtable(8) + ObjectFlags(4) + InternalIndex(4) + Class(8)
// + Name(8, FName) + Outer(8). Total size 0x28.
// For WITH_CASE_PRESERVING_NAME builds (FName = 16 bytes), all of these
// shift by 0x08 — use [`EngineLayout`] override to remap at runtime.
pub const UOBJECT_CLASS: usize = 0x10;
pub const UOBJECT_FNAME: usize = 0x18;
pub const UOBJECT_OUTER: usize = 0x20;

// ── UField layout (extends UObject) ──────────────────────────────────
pub const UFIELD_NEXT: usize = 0x28;

// ── UStruct layout (extends UField) ─────────────────────────────────
pub const USTRUCT_SUPER: usize = 0x40;
pub const USTRUCT_CHILDREN: usize = 0x48;       // UField* linked list (UFunctions)
pub const USTRUCT_CHILD_PROPERTIES: usize = 0x50; // FField* linked list (properties)
pub const USTRUCT_PROPERTIES_SIZE: usize = 0x58;

// ── UFunction layout (extends UStruct) ──────────────────────────────
// UStruct size on non-CPN UE5.3 is 0xB0 (after PropertyLink/RefLink/
// DestructorLink/PostConstructLink + ScriptAndPropertyObjectReferences
// + UnresolvedScriptProperties + UninitializedProperties). UFunction
// adds FunctionFlags(u32) then tail members, placing Func at +0xB0+0x28.
pub const UFUNCTION_FLAGS: usize = 0xB0;        // EFunctionFlags (u32)
pub const UFUNCTION_FUNC: usize = 0xD8;         // FNativeFuncPtr

// ── FField layout ───────────────────────────────────────────────────
pub const FFIELD_CLASS_PRIVATE: usize = 0x08;
pub const FFIELD_NEXT: usize = 0x18;
pub const FFIELD_NAME: usize = 0x20;

// ── FFieldClass ─────────────────────────────────────────────────────
pub const FFIELD_CLASS_NAME: usize = 0x00;

// ── FProperty layout (extends FField) ───────────────────────────────
pub const FPROPERTY_ARRAY_DIM: usize = 0x30;
pub const FPROPERTY_ELEMENT_SIZE: usize = 0x34;
pub const FPROPERTY_OFFSET: usize = 0x44;

// ── FBoolProperty extras (extends FProperty) ────────────────────────
// Four u8s appended *after* the FProperty base (size 0x70 on UE5.3 non-CPN):
// FieldSize, ByteOffset, ByteMask, FieldMask. `field_mask` is the single bit
// set for native bitfield booleans, or 0xFF for standard bool fields.
pub const FBOOL_PROP_FIELD_SIZE: usize = 0x70;
pub const FBOOL_PROP_BYTE_OFFSET: usize = 0x71;
pub const FBOOL_PROP_BYTE_MASK: usize = 0x72;
pub const FBOOL_PROP_FIELD_MASK: usize = 0x73;

// ── UEnum layout (extends UField) ───────────────────────────────────
// UField ends at +0x30, then FString CppType (16 bytes: ptr+num+max),
// then TArray<TPair<FName, int64>> Names at +0x40. Each pair is 16
// bytes (u32 ComparisonIndex + u32 Number + i64 Value).
pub const UENUM_NAMES: usize = 0x40;
pub const UENUM_VARIANT_STRIDE: usize = 16;

// ── Property subtype extras ─────────────────────────────────────────
pub const FSTRUCT_PROP_STRUCT: usize = 0x70;
pub const FOBJECT_PROP_CLASS: usize = 0x70;
pub const FARRAY_PROP_INNER: usize = 0x70;
pub const FMAP_PROP_KEY: usize = 0x70;
pub const FMAP_PROP_VALUE: usize = 0x78;
pub const FSET_PROP_ELEMENT: usize = 0x70;
pub const FENUM_PROP_ENUM: usize = 0x78;
