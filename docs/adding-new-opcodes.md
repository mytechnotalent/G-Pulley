# Adding New Opcodes

Copyright (c) 2026 Kevin Thomas (kevin@mytechnotalent.com)

Step-by-step guide for extending the SLEIGH spec when Wasmtime adds new Pulley instructions.

## When to Add Opcodes

Wasmtime's `pulley-interpreter` crate defines the canonical opcode list. When a new Wasmtime release adds instructions, bytecode compiled with that version will contain opcodes that G-Pulley shows as `undecoded_op`. Check the [pulley-interpreter changelog](https://crates.io/crates/pulley-interpreter) for opcode additions.

## Step-by-Step

### 1. Identify the New Opcode

Find the opcode number and encoding in Wasmtime's source:

```
wasmtime/crates/pulley-interpreter/src/lib.rs    # opcode enum
wasmtime/crates/pulley-interpreter/src/decode.rs  # encoding format
```

Note:
- The opcode byte value (e.g., `0x4b`)
- Operand format (XReg, BinaryOperands, immediate, etc.)
- Whether it's a primary opcode (1 byte) or extended (0xDC + u16)
- Semantic behavior (what the instruction computes)

### 2. Add the Instruction to the SLEIGH Spec

Edit `pulley.slaspec` (for pulley32) and `pulley64.slaspec` (for pulley64):

```sleigh
# -------------------------------------------------------------------
# 0x4b: xmul32 (BinaryOperands packed)
# -------------------------------------------------------------------
:xmul32 bop_dst, bop_src1, bop_src2 is op=0x4b; bop_dst & bop_src1 & bop_src2 {
    bop_dst = zext(bop_src1:4 * bop_src2:4);
}
```

Key rules:
- **Comment block**: Opcode number and mnemonic name
- **Constructor line**: `:mnemonic operands is pattern { semantics }`
- **Token matching**: Use existing tokens (`op`, `r1`/`r2`, `bop_dst`/`bop_src1`/`bop_src2`, `simm32`, etc.)
- **P-code semantics**: Match Wasmtime's behavior exactly

### 3. Handle pulley32 vs pulley64 Differences

For instructions that **don't involve addresses** (ALU, branches, comparisons):
- The SLEIGH code is **identical** in both slaspec files

For instructions that **compute addresses** (loads, stores, call_indirect):
- pulley32: `local addr:4 = r2:4 + simm32:4;`
- pulley64: `local addr:8 = r2 + sext(simm32:4);`

### 4. Add to the Analyzer (if needed)

If the new opcode is a **call variant** or **function prologue**, update `PulleyCwasmAnalyzer.java`:

```java
// In the byte-scanning loop, add detection for the new opcode
if (bytes[i] == NEW_CALL_OPCODE) {
    // Parse operands, resolve target, create function
}
```

### 5. Update Documentation

- Add the opcode to `docs/pulley-isa-reference.md`
- Update the instruction count in `README.md`
- Bump the version in `extension.properties` if shipping a release

### 6. Test

1. Compile a Wasm module with the new Wasmtime version (`wasmtime compile --target pulley32-...`)
2. Import the cwasm into Ghidra with G-Pulley
3. Verify the new instruction disassembles correctly
4. Check the decompiler output for correct semantics

## Extended Opcodes

Extended opcodes use the 0xDC prefix followed by a u16 LE opcode number:

```sleigh
# -------------------------------------------------------------------
# Extended 0x000c: new_extended_op dst, src
# -------------------------------------------------------------------
:new_extended_op r1, r2 is op=0xdc; extop=0x000c; r1; r2 {
    r1 = r2;
}
```

The `extop` token is already defined as a 16-bit field. Just add the new `extop=0xNNNN` value.

## Common Patterns

### 32-bit ALU (zero-extend result)

```sleigh
bop_dst = zext(bop_src1:4 OP bop_src2:4);
```

### Immediate variant

```sleigh
local val:4 = sext(simm8:1);   # or zext(imm8:1)
r1 = zext(r2:4 OP val);
```

### Load (pulley32)

```sleigh
local addr:4 = r2:4 + simm32:4;
r1 = zext(*:4 addr);
```

### Load (pulley64)

```sleigh
local addr:8 = r2 + sext(simm32:4);
r1 = zext(*:4 addr);
```

### Guarded load (pulley32)

```sleigh
local wasm_ptr:4 = ag32_wasm_addr:4 + ag32_offset:4;
local addr:4 = ag32_base:4 + wasm_ptr;
r1 = zext(*:4 addr);
```

### Guarded load (pulley64)

```sleigh
local off:8 = zext(ag32_offset:2);
local wasm_ptr:8 = ag32_wasm_addr + off;
local addr:8 = ag32_base + wasm_ptr;
r1 = zext(*:4 addr);
```
