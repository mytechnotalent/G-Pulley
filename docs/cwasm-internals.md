# cwasm Internals

Copyright (c) 2026 Kevin Thomas (kevin@mytechnotalent.com)

Technical details of the cwasm (compiled WebAssembly) binary format used by Wasmtime's Pulley interpreter.

## ELF Structure

A cwasm file is an **ELF64 little-endian** binary with:

- **e_ident[EI_CLASS]** = `ELFCLASS64` (2)
- **e_ident[EI_DATA]** = `ELFDATA2LSB` (1) — little-endian
- **e_machine** = `EM_NONE` (0) — no standard architecture
- **e_type** = `ET_DYN` (3) — shared object (position-independent)

The use of `EM_NONE` distinguishes cwasm from all native ELF binaries. G-Pulley's loader uses this as the primary detection criterion.

## Section Layout

### .text

Contains the Pulley bytecode. Functions are laid out sequentially with no padding or alignment between them. Each function starts with a `push_frame_save` (0xAA) or `push_frame` (0xA8) prologue and ends with a `ret` (0x01) instruction.

The section's virtual address (`sh_addr`) determines the base address for all PC-relative calculations. All `call` and branch offsets are relative to the start of each instruction within this section.

### .symtab / .strtab

When present (non-stripped), the symbol table contains `STT_FUNC` entries mapping function names to byte offsets within `.text`. Symbol names follow the pattern `function[N]` where N is the Wasm function index, or demangled names if debug info was preserved.

Each symbol entry (ELF64 `Elf64_Sym`, 24 bytes):

| Field    | Size | Description                        |
| -------- | ---- | ---------------------------------- |
| st_name  | 4 B  | Offset into .strtab                |
| st_info  | 1 B  | Binding (upper 4) + type (lower 4) |
| st_other | 1 B  | Visibility                         |
| st_shndx | 2 B  | Section index (.text)              |
| st_value | 8 B  | Byte offset within .text           |
| st_size  | 8 B  | Function size in bytes             |

### .rodata

Read-only data referenced by Pulley bytecode. Includes string literals and constant data used by the Wasm module. Accessed via `xpcadd` (PC-relative address load) instructions.

### .custom_*

Wasm custom sections preserved from the original `.wasm` component. These contain metadata like component model type information but are not executed.

## Embedded cwasm in ARM Firmware

When targeting embedded platforms (RP2350), the cwasm is compiled separately and included in the firmware via `include_bytes!()` in Rust:

```rust
static CWASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/app.cwasm"));
```

The entire cwasm ELF is stored verbatim in the ARM binary's `.rodata` section. G-Pulley's loader finds it by scanning for the ELF magic `7f 45 4c 46` followed by validation of `ELFCLASS64` + `ELFDATA2LSB` + `EM_NONE`.

## Stripping

Running `wasmtime compile` without `--debug-info` produces a cwasm with symbols. Stripping removes `.symtab` and `.strtab` but preserves `.text` (the bytecode is unchanged). G-Pulley's analyzer compensates by discovering functions through call target resolution and prologue detection.
