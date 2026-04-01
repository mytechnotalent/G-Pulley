# Reverse Engineering Workflow

Copyright (c) 2026 Kevin Thomas (kevin@mytechnotalent.com)

Techniques for analyzing Pulley bytecode in stripped firmware binaries.

## Overview

Pulley bytecode appears in two contexts:
1. **Standalone cwasm**: A `.cwasm` file from `wasmtime compile`
2. **Embedded in firmware**: A cwasm blob inside an ARM ELF (e.g., RP2350 firmware)

G-Pulley handles both. This guide focuses on practical analysis techniques once the bytecode is loaded.

## Initial Import

### Standalone cwasm

1. **File -> Import File** -> select the `.cwasm` file
2. G-Pulley auto-detects `ELF64 + EM_NONE` and selects Pulley language
3. Choose **Pulley:LE:32:default** (embedded/32-bit Wasm) or **Pulley:LE:64:default** (desktop/64-bit)
4. The loader imports `.text`, applies symbols (if present), and starts auto-analysis

### Embedded in ARM Firmware

1. Import the ARM `.elf` — the loader detects the embedded cwasm
2. Select Pulley language and import
3. Alternatively: open the ARM ELF normally, run **ExtractCwasmBlob.java**, save, then import the extracted cwasm separately

## Understanding the Call Convention

Pulley uses a simple register-based calling convention:

- **Arguments**: `x0` - `x7` (up to 8 registers, caller-saved)
- **Return value**: `x0`
- **Callee-saved**: `x16` - `x29`
- **Stack pointer**: `xsp`
- **Frame pointer**: `fp`
- **Return address**: `lr`

Every function begins with a frame setup:
```
push_frame_save #FRAME_SIZE, #REGMASK
```

This saves `lr`, `fp`, sets `fp = xsp`, then allocates `FRAME_SIZE` bytes of stack. The `REGMASK` indicates which callee-saved registers (x16-x29) are saved.

## Identifying Key Patterns

### Host Function Calls

Host-imported functions (GPIO, UART, timers) use `call_indirect_host`:

```
call_indirect_host #3    ; HOST IMPORT #3
```

The analyzer adds plate comments with the host function ID. Map these IDs to your WIT interface functions:

| ID  | WIT Function (example) |
| --- | ---------------------- |
| 0   | gpio::set-direction    |
| 1   | gpio::write            |
| 2   | timing::delay-ms       |
| 3   | uart::write-bytes      |

The mapping depends on the component's import order, defined in the `.wasm` component model metadata.

### Memory Access Patterns

#### Direct Offset (O32)

```
xload32le_o32  x0, x16, #0x10     ; Load from x16 + 0x10
```

Common for accessing struct fields or stack-relative data.

#### Guarded Heap Access (G32)

```
xload32le_g32  x0, [x17, x18, x3, #0x4]
```

This is a bounds-checked Wasm linear memory access:
- `x17` = heap base pointer (set by runtime)
- `x18` = heap bound
- `x3` = Wasm address (index from Wasm code)
- `#0x4` = static offset

The effective address is `heap_base + wasm_addr + offset`.

### Loop Detection

Backward branches indicate loops:

```
<loop_top>
    xload32le_g32  x5, [x17, x18, x3, #0]
    xadd32_u8      x3, x3, #4
    br_if_xult32   x3, x6, <loop_top>
```

The decompiler converts these to `while`/`for` loops in the C output.

### Switch/Jump Tables

Indirect jumps via computed addresses:

```
xpcadd         x5, <table_base>
xload32le_o32  x5, x5, #0
call_indirect  x5
```

## Stripped Binary Analysis

When symbols are absent:

1. **Function names**: Ghidra generates `FUN_xxxx` names — rename them as you identify their purpose
2. **Call graph**: Use **Window -> Function Call Graph** to visualize the call tree
3. **Cross-references**: Right-click a function -> **References -> Find References To** to see all callers
4. **String references**: If `.rodata` is loaded, strings can help identify functions (look for `xpcadd` instructions that reference constant data)

## Tips

- **Start from host calls**: `call_indirect_host` sites are the interface between Wasm and the host platform — they reveal the module's I/O behavior
- **Follow x0**: The return value register carries results between functions — trace it to understand data flow
- **Frame size tells complexity**: `push_frame_save #SIZE, #MASK` — larger frame sizes indicate more local variables and more complex functions
- **Guarded vs unguarded**: Guarded accesses (G32) are Wasm linear memory operations; unguarded (O32, Z) are internal runtime data structures
