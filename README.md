# G-Pulley

Ghidra processor module for **Pulley** — Wasmtime's portable bytecode interpreter ISA (v43.0.0). Disassembles and decompiles Pulley bytecode found in compiled WebAssembly modules (cwasm). Works with both **stripped** and **non-stripped** binaries. Supports both **pulley32** (32-bit address space) and **pulley64** (64-bit address space) targets.

## Author

**Kevin Thomas** — kevin@mytechnotalent.com

## What Is Pulley?

Pulley is Wasmtime's built-in portable interpreter. When a platform has no Cranelift native-code backend (e.g., Cortex-M33 / RP2350), Wasmtime compiles WebAssembly to Pulley bytecode instead of machine code. The result is stored in **cwasm** (compiled WebAssembly) format — an ELF64 binary with Pulley bytecode in its `.text` section.

```
                      wasmtime compile
  .wasm component  ─────────────────────>  cwasm ELF64
  (WebAssembly        --target pulley32     .text = Pulley bytecode
   Component Model)                         .symtab = function symbols
```

In embedded firmware (RP2350, etc.), the cwasm is embedded as a `static` byte array in the ARM binary's `.rodata` section. At runtime, the Pulley interpreter dispatches the bytecode instruction-by-instruction.

## cwasm Binary Format

A cwasm file is an **ELF64 little-endian** binary (`e_machine = EM_NONE`) with:

| Section       | Contents                                          |
| ------------- | ------------------------------------------------- |
| `.text`       | Pulley bytecode (executable code)                 |
| `.rodata`     | Read-only data (string literals, jump tables)     |
| `.data`       | Initialized mutable data                          |
| `.custom_...` | Wasm custom sections (names, component metadata)  |
| `.symtab`     | Symbol table — function names and byte boundaries |
| `.strtab`     | String table for symbol names                     |
| `.shstrtab`   | Section header string table                       |

The `.symtab` maps Wasm function indices to byte offsets and sizes within `.text`. Entries look like `function[15]` (the Wasm function index). When symbols are present (non-stripped), G-Pulley applies exact function boundaries and names. When symbols are absent (stripped), the Java analyzer discovers functions by tracing `call` targets and `push_frame_save` prologues.

### How cwasm Gets Embedded in Firmware

```
                    wasmtime compile
  app.wasm  ──────────────────────────>  app.cwasm  (ELF64, Pulley bytecode)
                  --target pulley32

                    Rust build.rs
  app.cwasm ──────────────────────────>  static CWASM: &[u8] = include_bytes!(...)

                    cargo build
  firmware.rs ────────────────────────>  firmware.elf  (ARM ELF32)
  + CWASM blob                            .rodata contains the entire cwasm ELF bytes
```

At runtime, the firmware passes `&CWASM` to `wasmtime::Module::deserialize()`, which memory-maps the ELF sections and creates a runnable module. The Pulley interpreter (`pulley_interpreter::interp`) then executes `.text` bytecode via a dispatch loop.

## Pulley ISA Overview

Pulley is a **register-based**, **variable-length**, **little-endian** bytecode ISA.

### Registers

| Register          | Encoding | Purpose                       |
| ----------------- | -------- | ----------------------------- |
| `x0` - `x15`      | 0 - 15   | Caller-saved (args, temps)    |
| `x16` - `x29`     | 16 - 29  | Callee-saved                  |
| `xsp` (x30)       | 30       | Stack pointer                 |
| `spilltmp0` (x31) | 31       | Internal spill temporary      |
| `lr`              | —        | Link register (return addr)   |
| `fp`              | —        | Frame pointer                 |
| `f0` - `f31`      | 0 - 31   | Float/vector registers (128b) |

Registers are 64-bit internally. The SLEIGH spec defines both 8-byte (`x0`) and 4-byte sub-register (`x0l`) aliases. In pulley32 mode, pointers use the low 32 bits (32-bit address space). In pulley64 mode, the full 64-bit register is used for addressing.

### Opcode Encoding

- **Primary opcodes**: 1 byte (0x00 - 0xDB), 220 opcodes
- **Extended opcodes**: 3+ bytes — 0xDC prefix + u16 LE extended opcode
- **All multi-byte fields**: little-endian

### Operand Types

| Type              | Size | Description                                                              |
| ----------------- | ---- | ------------------------------------------------------------------------ |
| XReg              | 1 B  | Register index 0-31 (full byte, bits 4:0 used)                           |
| BinaryOperands    | 2 B  | Packed u16 LE: `dst[4:0]`, `src1[9:5]`, `src2[14:10]`                    |
| BinaryOperands/U6 | 2 B  | Packed u16 LE: `dst[4:0]`, `src[9:5]`, `imm6[15:10]`                     |
| PcRelOffset       | 4 B  | Signed i32 LE, relative to **start** of instruction                      |
| AddrO32           | 5 B  | XReg (1B base) + i32 (4B signed offset)                                  |
| AddrG32           | 4 B  | Packed u32 LE: `off[15:0]`, `wasm[20:16]`, `bound[25:21]`, `base[30:26]` |
| UpperRegSet       | 2 B  | Bitmask u16 — bit N saves register x(N+16)                               |

#### BinaryOperands Packing (u16 LE)

```
15            10 9       5 4     0
+──────────────+─────────+───────+
|   src2 (5b)  | src1(5b)| dst(5b)|
+──────────────+─────────+───────+
```

Example: bytes `20 42` -> u16 = 0x4220 -> dst = x0, src1 = x17, src2 = x16 -> `xadd32 x0, x17, x16`

#### AddrG32 Packing (u32 LE)

```
31 30       26 25      21 20     16 15            0
+──+─────────+──────────+─────────+────────────────+
|  | base(5b)| bound(5b)| wasm(5b)|  offset (16b)  |
+──+─────────+──────────+─────────+────────────────+
```

Guarded memory access: `address = heap_base + wasm_addr + offset`, bounds-checked against `heap_bound`.

## Project Structure

```
G-Pulley/
├── README.md                           # This file
├── extension.properties                # Ghidra extension metadata
├── Module.manifest                     # Module class: PROCESSOR
├── build.gradle                        # Gradle build (compile + zip)
├── data/
│   └── languages/
│       ├── pulley.slaspec              # SLEIGH processor specification — pulley32
│       ├── pulley64.slaspec            # SLEIGH processor specification — pulley64
│       ├── pulley.ldefs                # Language definitions (32-bit and 64-bit)
│       ├── pulley.pspec                # Processor spec (PC, register groups)
│       ├── pulley.cspec                # Compiler spec — pulley32 (pointer_size=4)
│       ├── pulley64.cspec              # Compiler spec — pulley64 (pointer_size=8)
│       └── pulley.opinion              # Format opinion
├── src/
│   └── main/java/gpulley/
│       ├── PulleyCwasmLoader.java      # ELF loader — imports cwasm into Ghidra
│       └── PulleyCwasmAnalyzer.java    # Post-load analyzer — discovers functions
├── ghidra_scripts/
│   └── ExtractCwasmBlob.java           # Script: extract cwasm from ARM ELF
└── docs/                               # (reserved for additional documentation)
```

### Component Descriptions

**`pulley.slaspec`** — SLEIGH instruction specification for pulley32 (32-bit address space). Defines all tokens, register attachments, and ~65 instruction constructors covering: control flow (call, ret, jump), branches (conditional on register tests, register-register comparisons, register-vs-immediate comparisons), register moves and constants, 32/64-bit arithmetic, shifts (register and U6 immediate), bitwise ops (AND/OR/XOR/NOT with register and immediate variants), comparisons, count/extend ops (clz, ctz, zext, sext), memory loads/stores (offset O32, zero-checked Z, guarded G32), frame ops (push/pop_frame, push/pop_frame_save), and extended opcodes (trap, call_indirect_host, xpcadd, xmov_fp/lr). Includes an `undecoded_op` catch-all for unrecognized opcodes.

**`pulley64.slaspec`** — SLEIGH instruction specification for pulley64 (64-bit address space). Same opcodes and encoding as pulley32. Differences: `ram size=8`, branch targets export 8-byte addresses, load/store address computations use full 64-bit registers with `sext()` on 32-bit offsets, `call_indirect` uses 8-byte function pointers. All 32-bit ALU operations (xadd32, xsub32, etc.) remain unchanged — they still operate on the low 32 bits and zero-extend.

**`PulleyCwasmLoader.java`** — Ghidra `AbstractLibrarySupportLoader` subclass. Handles two scenarios:
1. **Standalone cwasm**: Detects ELF64 + `EM_NONE` (Pulley). Parses section headers, loads `.text` as an executable memory block, parses `.symtab`/`.strtab` to create function labels.
2. **Embedded in ARM ELF**: Detects ELF32 + `EM_ARM`, scans all bytes for a nested ELF64 + `EM_NONE` header (the embedded cwasm blob in `.rodata`), extracts and loads it.

**`PulleyCwasmAnalyzer.java`** — Post-load byte analyzer. Scans the loaded `.text` bytecode to:
- Create functions at `push_frame_save` / `push_frame` prologues
- Resolve `call` / `call2` / `call3` / `call4` PC-relative targets and create functions at destinations
- Annotate `call_indirect_host` sites with plate comments showing host function IDs
- Mark `trap` instructions with end-of-line comments

**`ExtractCwasmBlob.java`** — Ghidra script for extracting the cwasm from an already-loaded ARM ELF. Searches memory blocks for the embedded ELF64 magic, computes the extent from section headers, and saves to a file.

## Installation

### Prerequisites

- Ghidra 11.x or later
- Java 17+

### Option A: Build with Gradle

```sh
cd G-Pulley

# Set your Ghidra installation path
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x

# Build the extension zip
gradle build
# -> build/dist/G-Pulley-1.0.zip
```

In Ghidra: **File -> Install Extensions -> Add (+)** -> select `G-Pulley-1.0.zip`. Restart Ghidra.

### Option B: Manual Copy

```sh
GHIDRA_DIR=/path/to/ghidra_11.x

# Copy language files
mkdir -p "$GHIDRA_DIR/Ghidra/Processors/Pulley/data/languages"
cp G-Pulley/data/languages/* "$GHIDRA_DIR/Ghidra/Processors/Pulley/data/languages/"

# Copy compiled Java classes (if built)
mkdir -p "$GHIDRA_DIR/Ghidra/Processors/Pulley/lib"
cp G-Pulley/bin/*.class "$GHIDRA_DIR/Ghidra/Processors/Pulley/lib/"

# Copy Ghidra script
cp G-Pulley/ghidra_scripts/*.java ~/ghidra_scripts/
```

Restart Ghidra. The **Pulley:LE:32:default** and **Pulley:LE:64:default** languages appear in the processor selector.

## Usage

### Choosing 32-bit vs 64-bit

| Target                      | Language             | When to use                               |
| --------------------------- | -------------------- | ----------------------------------------- |
| `--target pulley32-...`     | Pulley:LE:32:default | Embedded (RP2350), 32-bit Wasm memory     |
| `--target pulley64-...`     | Pulley:LE:64:default | Desktop/server, 64-bit host address space |
| ARM ELF with embedded cwasm | Pulley:LE:32:default | Always 32-bit (firmware uses pulley32)    |

For standalone cwasm files, the loader offers both 32-bit (preferred) and 64-bit. Select the one matching your `wasmtime compile --target` setting.

### Workflow 1: Import a Standalone cwasm File

1. **File -> Import File** -> select the `.cwasm` file
2. The **Pulley Cwasm Loader** auto-detects the ELF64/EM_NONE format
3. Ghidra selects **Pulley:LE:32:default** as the language
4. Click **OK** — the loader imports `.text`, applies symbols, starts disassembly
5. The **Pulley Cwasm Analyzer** runs automatically to discover additional functions

### Workflow 2: Import ARM Firmware Containing Embedded cwasm

1. **File -> Import File** -> select the ARM `.elf` firmware
2. The loader detects the embedded cwasm blob and offers the Pulley language
3. Select **Pulley:LE:32:default** -> **OK**
4. The loader extracts the inner cwasm ELF and loads the Pulley bytecode

### Workflow 3: Extract cwasm from an Already-Open ARM ELF

If the ARM firmware is already open in Ghidra (with the ARM processor):

1. **Script Manager** -> run **ExtractCwasmBlob.java**
2. Save the extracted cwasm to a file
3. Import the saved file as a new program (auto-detected as Pulley)

## Stripped vs Non-Stripped Binaries

| Feature             | Non-Stripped cwasm          | Stripped cwasm               |
| ------------------- | --------------------------- | ---------------------------- |
| `.symtab` present   | Yes                         | No                           |
| Function boundaries | Exact (from symbol table)   | Discovered by analyzer       |
| Function names      | `function[N]` or demangled  | Auto-generated (`FUN_xxxx`)  |
| Discovery method    | Symbol table parsing        | Call targets + prologue scan |
| Decompiler quality  | Full (with named functions) | Full (with auto-named funcs) |

For stripped binaries, the `PulleyCwasmAnalyzer` finds function entry points by:
1. **Call target resolution**: Every `call`/`call2`/`call3`/`call4` instruction has a PC-relative offset that resolves to an absolute address — the analyzer creates a function at each target.
2. **Prologue detection**: Pulley functions begin with `push_frame_save` (opcode 0xAA) or `push_frame` (opcode 0xA8) — the analyzer creates functions at these patterns.

Both methods produce complete function coverage. The decompiler works identically in both cases; non-stripped just provides better naming.

## Instruction Categories

| Category     | Opcodes                                            | Count |
| ------------ | -------------------------------------------------- | ----- |
| Control flow | ret, call, call1-4, call_indirect, jump            | ~8    |
| Branches     | br_if32, br_if_xeq32, br_if_xult32_u8, ...         | ~18   |
| Register ops | xmov, xzero, xone, xconst8/16/32, xselect32        | ~7    |
| Arithmetic   | xadd32, xsub32, xneg32, xmin32_u, xmax32_u         | ~8    |
| Shifts       | xshl32, xshr32_u, xshl32_u6, xshr32_u_u6, xrotl32  | ~6    |
| Bitwise      | xband32, xbor32, xbxor32, xbnot32 (+imm variants)  | ~8    |
| Comparison   | xeq32, xult32                                      | ~2    |
| Count/Extend | xclz32, xctz32, zext8, zext32                      | ~4    |
| Memory (O32) | xload32le_o32, xstore32le_o32, xload64le_o32, ...  | ~6    |
| Memory (Z)   | xload8_u32_z, xload32le_z, xstore8_z, xstore32le_z | ~6    |
| Memory (G32) | xload32le_g32, xstore32le_g32, xstore64le_g32, ... | ~4    |
| Frame ops    | push_frame, pop_frame, push/pop_frame_save         | ~4    |
| Extended     | trap, call_indirect_host, xpcadd, xmov_fp, xmov_lr | ~6    |

Total: ~65 instruction definitions + `undecoded_op` catch-all.

## Decompiler Output

With the calling convention defined in `pulley.cspec`:
- Arguments passed in `x0` - `x7`, return value in `x0`
- Callee-saved: `x16` - `x29`, `xsp`, `fp`
- Stack grows downward
- Return address stored in `lr`

Ghidra's decompiler produces readable C-like output showing:
- Function calls with resolved PC-relative targets
- Memory accesses through `heap_base + wasm_addr + offset` patterns (guarded loads/stores)
- Branch conditions and loop structures from conditional branch instructions
- Host function calls annotated with `HOST IMPORT #N` plate comments

## Understanding the Disassembly: Function Map

Pulley bytecode compiled from a Wasm component (via `wit-bindgen` + `dlmalloc`) follows a predictable structure. The function index space starts after imported functions (which have no bytecode bodies), so defined functions begin at index 2 or higher depending on the number of WIT imports.

### Typical Function Layout

| Function Index             | Source-Level Meaning                  | Signature                             |
| -------------------------- | ------------------------------------- | ------------------------------------- |
| function[0], function[1]   | Imported host functions (no bytecode) | Defined by WIT imports                |
| function[2]                | `cabi_realloc` no-op stub             | Empty: push_frame -> pop_frame -> ret |
| function[3]                | `dlmalloc` (malloc core)              | Large, complex bit manipulation       |
| function[4]                | `dlfree` (free core)                  | Calls several internal helpers        |
| function[5] - function[13] | dlmalloc internal helpers             | Called only from malloc/free          |
| function[14]               | `cabi_realloc` export stub            | Small trampoline                      |
| **function[15]**           | **Guest app logic (`run()`)**         | Contains `call_indirect_host` calls   |
| function[16]               | `panic()` handler                     | Tiny: `loop { spin_loop() }`          |
| function[17]               | `dlrealloc` (realloc)                 | Called by `cabi_realloc`              |
| function[18]               | `cabi_realloc` wrapper                | Thin trampoline -> function[17]       |

> **Note:** ~95% of the bytecode is `dlmalloc` allocator code, not application logic. This is normal — `wit-bindgen` requires `cabi_realloc` which pulls in the allocator. The actual guest `run()` function is typically small.

### Trampolines and Builtins

| Symbol                                    | Purpose                                                             |
| ----------------------------------------- | ------------------------------------------------------------------- |
| `signatures[N]::wasm_to_array_trampoline` | Guest-to-host call adapters (how guest calls WIT imports)           |
| `array_to_wasm_trampoline[N]`             | Host-to-guest entry points (how host calls exported Wasm functions) |
| `component-lower-import[N]`               | WIT import lowering (one per imported interface function)           |
| `component-trampolines[N]`                | Component model call adapters                                       |
| `wasmtime_builtin_memory_grow`            | Wasm linear memory expansion                                        |
| `wasmtime_builtin_memory_copy`            | Wasm linear memory copy (memcpy)                                    |

### Identifying Host Calls

Inside the guest app function (e.g., function[15]), `call_indirect_host` instructions represent calls to WIT-imported host functions. The operand byte is the host function ID:

```
dc 01 00 03    call_indirect_host #3    ; HOST IMPORT #3
```

These IDs map to `component-lower-import[N]` entries, which correspond to WIT imports in declaration order. For example, with imports `gpio.set-high`, `gpio.set-low`, `timing.delay-ms`:

| Host ID | component-lower-import    | WIT Function       |
| ------- | ------------------------- | ------------------ |
| 0       | component-lower-import[0] | `gpio::set_high`   |
| 1       | component-lower-import[1] | `gpio::set_low`    |
| 2       | component-lower-import[2] | `timing::delay_ms` |

### Finding Your App Logic

1. Navigate to **function[15]** (or the highest-numbered non-trampoline function with `call_indirect_host` instructions)
2. Look for `call_indirect_host` — each one is a WIT import call (GPIO, timing, etc.)
3. The surrounding register setup (`xconst8`, `xmov`) loads arguments (pin numbers, delay values)
4. Branch/loop structures (`br_if32`, `jump`) correspond to Rust `loop {}` and `if` blocks

## Limitations

- **Float/vector registers**: `f0`-`f31` are declared in `pspec` but no float instructions are implemented in the SLEIGH spec yet. Add them if analyzing float-heavy Wasm modules.
- **Extended opcodes**: Only 6 of ~310 extended opcodes are implemented (trap, call_indirect_host, xpcadd, xmov_fp, xmov_lr, profile). Others will hit `undecoded_op`.
- **Pulley version**: Targets `pulley-interpreter` v43.0.0. Opcode numbering may shift in future Wasmtime releases.

## Docs

The `docs/` directory contains supplemental documentation:

- **[pulley-isa-reference.md](docs/pulley-isa-reference.md)** — Full opcode table with encoding details, operand formats, and p-code semantics
- **[cwasm-internals.md](docs/cwasm-internals.md)** — ELF section layout, symbol table format, and embedded cwasm detection
- **[adding-new-opcodes.md](docs/adding-new-opcodes.md)** — Step-by-step guide for extending the SLEIGH spec when Wasmtime adds instructions
- **[reverse-engineering-workflow.md](docs/reverse-engineering-workflow.md)** — Techniques for analyzing Pulley bytecode in stripped firmware binaries

## References

- [Wasmtime Pulley RFC](https://github.com/bytecodealliance/rfcs/pull/35)
- [pulley-interpreter crate (v43.0.0)](https://crates.io/crates/pulley-interpreter)
- [Ghidra SLEIGH documentation](https://ghidra.re/courses/languages/html/sleigh.html)
- [Wasmtime cwasm code memory](https://github.com/bytecodealliance/wasmtime/tree/main/crates/wasmtime/src/runtime/code_memory.rs)

## License

MIT License — Copyright (c) 2026 Kevin Thomas (kevin@mytechnotalent.com)
