# ue5-dumper

A small, self-contained **Unreal Engine 5 SDK dumper** for Linux. Attaches to a
running UE5 game (native or under Wine/Proton), locates the engine globals
(`GNames`, `GObjects`, `GWorld`) at runtime via pattern scanning, and emits:

- `sdk_dump.json` — every `UClass`/`UScriptStruct` with its properties, sizes,
  offsets, parent chain, and `UFunction` signatures.
- `sdk.rs` *(optional)* — `#[repr(C)]` Rust structs with parent embedding and
  correct padding, ready to use with raw-memory readers.
- `chain.rs` *(optional)* — the standard `GWorld → LocalPlayer → PlayerController → Pawn`
  pointer-chain offsets, extracted from the dump.

No Windows kernel driver, no DLL injection, no root. Just `process_vm_readv(2)`.

## Requirements

- Linux (x86_64)
- `ptrace_scope` permissive enough to allow `process_vm_readv` against the
  target PID. Either:
  - Run the dumper as the same user that owns the game process, **and**
  - `sysctl kernel.yama.ptrace_scope=0` (or run the dumper with `CAP_SYS_PTRACE`)
- A running UE5 game. Windows builds work through Wine/Proton — the `.exe` name
  appears in `/proc/<pid>/cmdline` exactly as on Windows.

## Build

```bash
cargo build --release
```

The binary lands at `target/release/ue5-dumper`.

## Usage

```
ue5-dumper --process <NAME> [OPTIONS]
```

Minimum example:

```bash
# Native Linux UE5 game
ue5-dumper --process MyGame-Linux-Shipping

# Windows UE5 game running under Proton
ue5-dumper --process MyGame-Win64-Shipping.exe
```

Full set of flags (see `ue5-dumper --help` for descriptions):

| Flag | Effect |
|------|--------|
| `-p`, `--process <NAME>` | **Required.** Substring matched against `/proc/<pid>/cmdline`. |
| `-f`, `--filter <PAT>` | Only dump classes whose name or full path contains `PAT`. |
| `--rust` | Also emit `sdk.rs`. |
| `--chain` | Also emit `chain.rs` (player-pawn offsets). |
| `--no-json` | Skip the JSON dump (useful with `--rust` / `--chain` only). |
| `--json-out <PATH>` | JSON output path (default `sdk_dump.json`). |
| `--rust-out <PATH>` | Rust output path (default `sdk.rs`). |
| `--chain-out <PATH>` | Chain output path (default `chain.rs`). |
| `-h`, `--help` | Show usage. |
| `-V`, `--version` | Show version. |

## How it works

1. **Attach.** Read `/proc/*/cmdline` to find the PID, `/proc/<pid>/maps` for
   the image base.
2. **Scan.** Parse the PE/ELF header to locate `.text`, then scan for
   `LEA`/`MOV` with RIP-relative addressing and validate each candidate:
   - `GNames` — decode block 0 entry 0 and check it says `"None"`.
   - `GObjects` — `NumElements` is sane and the first objects' class names
     include `Class`/`Package`/`Function`.
   - `GWorld` — the pointed-to `UObject`'s class name resolves to `"World"`.
3. **Walk.** Iterate `FUObjectArray`, pick up every `UClass`/`UScriptStruct`,
   follow `ChildProperties` (FField chain) for layout and `Children` (UField
   chain) for functions.
4. **Emit.** JSON always, Rust bindings and pointer-chain optionally.

## Supported layouts

| Feature | Status |
|---------|--------|
| Shipping FName (header `>> 6`, stride 2) | ✓ |
| Case-preserving FName (4-byte ComparisonId, header `>> 1`, stride 4) | ✓ |
| Chunked `FUObjectArray` | ✓ |
| `FField`/`FProperty` layout (UE 4.25+) | ✓ |

Per-game layout quirks (e.g. games that shift `UObject.Outer` by 8 bytes for
their FName display copy) are handled by the constants in
[`src/ue/offsets.rs`](src/ue/offsets.rs). If your target uses a different
variant, edit that file — nothing else is game-specific.

## Output example

```json
{
  "num_objects": 427310,
  "classes": [
    {
      "name": "PlayerController",
      "full_name": "CoreUObject.Class.Engine.PlayerController",
      "parent": "Controller",
      "size": 2032,
      "properties": [
        { "name": "Player", "type": "ObjectProperty", "offset": 1024, "size": 8, "array_dim": 1, "inner_type": "Player" },
        { "name": "AcknowledgedPawn", "type": "ObjectProperty", "offset": 1992, "size": 8, "array_dim": 1, "inner_type": "Pawn" }
      ],
      "functions": [ ... ]
    }
  ]
}
```

## Project layout

```
src/
├── main.rs         — CLI
├── mem.rs          — process_vm_readv wrapper
├── scanner.rs      — PE parsing, LEA/MOV scanning, global validation
├── codegen.rs      — sdk.rs + chain.rs emitters
└── ue/
    ├── offsets.rs  — UE5 struct layout constants (edit for engine-variant tweaks)
    ├── fname.rs    — FNamePool decoder, auto-detects shipping vs. case-preserving
    ├── objects.rs  — FUObjectArray walker
    └── props.rs    — FField/UFunction walker + dump types
```

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Disclaimer

This tool reads memory from a process you own. That's legal on your own
machine for research, modding, and interop work. Using it against online
multiplayer games may violate their Terms of Service and is your problem,
not mine. Don't ship cheats with my name on them.
