# Pulley ISA Reference

Copyright (c) 2026 Kevin Thomas (kevin@mytechnotalent.com)

Full opcode table for the Wasmtime Pulley bytecode ISA v43.0.0.

## Opcode Map

### Primary Opcodes (1-byte, 0x00 - 0xDB)

| Opcode | Mnemonic           | Operands                      | Description                                      |
| ------ | ------------------ | ----------------------------- | ------------------------------------------------ |
| 0x00   | nop                | —                             | No operation                                     |
| 0x01   | ret                | —                             | Return to caller via lr                          |
| 0x02   | call               | PcRelOffset                   | Call function at PC-relative offset              |
| 0x03   | call1              | XReg, PcRelOffset             | Call with 1 argument                             |
| 0x04   | call2              | XReg, XReg, PcRelOffset       | Call with 2 arguments                            |
| 0x05   | call3              | XReg, XReg, XReg, PcRelOffset | Call with 3 arguments                            |
| 0x06   | call4              | XReg x4, PcRelOffset          | Call with 4 arguments                            |
| 0x07   | call_indirect      | XReg                          | Call through register (function pointer)         |
| 0x08   | jump               | PcRelOffset                   | Unconditional branch                             |
| 0x0a   | br_if32            | XReg, PcRelOffset             | Branch if low 32 bits nonzero                    |
| 0x0b   | br_if_not32        | XReg, PcRelOffset             | Branch if low 32 bits zero                       |
| 0x0c   | br_if_xeq32        | XReg, XReg, PcRelOffset       | Branch if equal (32-bit)                         |
| 0x0d   | br_if_xneq32       | XReg, XReg, PcRelOffset       | Branch if not equal (32-bit)                     |
| 0x10   | br_if_xult32       | XReg, XReg, PcRelOffset       | Branch if unsigned less than (32-bit)            |
| 0x11   | br_if_xulteq32     | XReg, XReg, PcRelOffset       | Branch if unsigned less or equal (32-bit)        |
| 0x18   | br_if_xeq32_i8     | XReg, i8, PcRelOffset         | Branch if equal to sign-extended i8              |
| 0x1a   | br_if_xneq32_i8    | XReg, i8, PcRelOffset         | Branch if not equal to sign-extended i8          |
| 0x24   | br_if_xult32_u8    | XReg, u8, PcRelOffset         | Branch if unsigned less than zero-extended u8    |
| 0x25   | br_if_xult32_u32   | XReg, u32, PcRelOffset        | Branch if unsigned less than u32                 |
| 0x28   | br_if_xugt32_u8    | XReg, u8, PcRelOffset         | Branch if unsigned greater than zero-extended u8 |
| 0x29   | br_if_xugt32_u32   | XReg, u32, PcRelOffset        | Branch if unsigned greater than u32              |
| 0x2a   | br_if_xugteq32_u8  | XReg, u8, PcRelOffset         | Branch if unsigned >= zero-extended u8           |
| 0x2b   | br_if_xugteq32_u32 | XReg, u32, PcRelOffset        | Branch if unsigned >= u32                        |
| 0x41   | xmov               | XReg, XReg                    | Register copy (64-bit)                           |
| 0x42   | xzero              | XReg                          | Set register to 0                                |
| 0x43   | xone               | XReg                          | Set register to 1                                |
| 0x44   | xconst8            | XReg, i8                      | Load sign-extended 8-bit immediate               |
| 0x45   | xconst16           | XReg, i16                     | Load sign-extended 16-bit immediate              |
| 0x46   | xconst32           | XReg, i32                     | Load sign-extended 32-bit immediate              |
| 0x48   | xadd32             | BinaryOperands                | 32-bit add, zero-extend to 64                    |
| 0x49   | xadd32_u8          | XReg, XReg, u8                | 32-bit add with zero-extended u8 immediate       |
| 0x4a   | xadd32_u32         | XReg, XReg, u32               | 32-bit add with u32 immediate                    |
| 0x50   | xsub32             | BinaryOperands                | 32-bit subtract, zero-extend to 64               |
| 0x51   | xsub32_u8          | XReg, XReg, u8                | 32-bit subtract with zero-extended u8 immediate  |
| 0x5e   | xclz32             | XReg, XReg                    | Count leading zeros (32-bit)                     |
| 0x60   | xctz32             | XReg, XReg                    | Count trailing zeros (32-bit)                    |
| 0x66   | xshl32             | BinaryOperands                | 32-bit shift left (masked by 0x1f)               |
| 0x68   | xshr32_u           | BinaryOperands                | 32-bit unsigned shift right (masked by 0x1f)     |
| 0x6c   | xshl32_u6          | BinaryOperands/U6             | 32-bit shift left with 6-bit immediate           |
| 0x6e   | xshr32_u_u6        | BinaryOperands/U6             | 32-bit unsigned shift right with 6-bit immediate |
| 0x72   | xneg32             | XReg, XReg                    | 32-bit negate, zero-extend to 64                 |
| 0x7a   | xeq32              | BinaryOperands                | 32-bit equality comparison (result 0 or 1)       |
| 0x7e   | xult32             | BinaryOperands                | 32-bit unsigned less-than (result 0 or 1)        |
| 0x84   | xload32le_o32      | XReg, XReg, i32               | Load 32-bit LE from base + signed offset         |
| 0x86   | xload64le_o32      | XReg, XReg, i32               | Load 64-bit LE from base + signed offset         |
| 0x88   | xstore32le_o32     | XReg, i32, XReg               | Store 32-bit LE to base + signed offset          |
| 0x89   | xstore64le_o32     | XReg, i32, XReg               | Store 64-bit LE to base + signed offset          |
| 0x8a   | xload8_u32_z       | XReg, XReg, i32               | Load byte, zero-extend to 64                     |
| 0x8e   | xload32le_z        | XReg, XReg, i32               | Load 32-bit LE (zero-checked addressing)         |
| 0x90   | xstore8_z          | XReg, i32, XReg               | Store byte (zero-checked addressing)             |
| 0x92   | xstore32le_z       | XReg, i32, XReg               | Store 32-bit LE (zero-checked addressing)        |
| 0x98   | xload32le_g32      | XReg, AddrG32                 | Guarded load 32-bit LE                           |
| 0x9a   | xload64le_z        | XReg, XReg, i32               | Load 64-bit LE (zero-checked addressing)         |
| 0x9c   | xstore32le_g32     | AddrG32, XReg                 | Guarded store 32-bit LE                          |
| 0x9e   | xstore64le_g32     | AddrG32, XReg                 | Guarded store 64-bit LE                          |
| 0x9f   | xload32le_g32bne   | XReg, AddrG32                 | Guarded load 32-bit LE with bounds-not-equal     |
| 0xa8   | push_frame         | —                             | Push lr + fp, set fp = sp                        |
| 0xa9   | pop_frame          | —                             | Restore fp + lr, return sp to fp                 |
| 0xaa   | push_frame_save    | u16, UpperRegSet              | Push frame + allocate stack + save regs          |
| 0xab   | pop_frame_restore  | u16, UpperRegSet              | Restore regs + deallocate stack + pop frame      |
| 0xb0   | zext32             | XReg, XReg                    | Zero-extend 32-bit to 64-bit                     |
| 0xb4   | zext8              | XReg, XReg                    | Zero-extend 8-bit to 64-bit                      |
| 0xbe   | xband32            | BinaryOperands                | 32-bit bitwise AND, zero-extend to 64            |
| 0xbf   | xband32_s8         | XReg, XReg, i8                | 32-bit AND with sign-extended i8                 |
| 0xc1   | xbnot32            | XReg, XReg                    | 32-bit bitwise NOT, zero-extend to 64            |
| 0xc4   | xbor32             | BinaryOperands                | 32-bit bitwise OR, zero-extend to 64             |
| 0xc5   | xbor32_s8          | XReg, XReg, i8                | 32-bit OR with sign-extended i8                  |
| 0xc8   | xrotl32            | BinaryOperands                | 32-bit rotate left                               |
| 0xcb   | xbxor32_s8         | XReg, XReg, i8                | 32-bit XOR with sign-extended i8                 |
| 0xcc   | xband32_s32        | XReg, XReg, i32               | 32-bit AND with sign-extended i32                |
| 0xd2   | xmin32_u           | BinaryOperands                | 32-bit unsigned minimum                          |
| 0xd4   | xmax32_u           | BinaryOperands                | 32-bit unsigned maximum                          |
| 0xda   | xselect32          | XReg x4                       | Conditional select (if cond != 0)                |
| 0xdc   | (extended prefix)  | u16 LE extended opcode        | See Extended Opcodes below                       |

### Extended Opcodes (0xDC + u16 LE)

| ExtOp  | Mnemonic           | Operands          | Description                            |
| ------ | ------------------ | ----------------- | -------------------------------------- |
| 0x0000 | trap               | —                 | Unconditional trap                     |
| 0x0001 | call_indirect_host | u8                | Call host-imported function by ID      |
| 0x0002 | xpcadd             | XReg, PcRelOffset | Load PC-relative address into register |
| 0x0003 | xmov_fp            | XReg              | Copy frame pointer to register         |
| 0x0004 | xmov_lr            | XReg              | Copy link register to register         |
| 0x000b | profile            | i32               | Profiling hint (no-op in interpreter)  |

## Operand Encoding Details

### BinaryOperands (u16 LE)

Three-register ALU operations pack `dst`, `src1`, `src2` into a single 16-bit little-endian word:

```
Bits:  [4:0] = dst   [9:5] = src1   [14:10] = src2   [15] = unused
```

### BinaryOperands/U6 (u16 LE)

Shift-by-immediate operations pack `dst`, `src`, and a 6-bit unsigned immediate:

```
Bits:  [4:0] = dst   [9:5] = src   [15:10] = imm6
```

### AddrG32 (u32 LE)

Guarded heap memory access packs four fields into a single 32-bit word:

```
Bits:  [15:0] = offset (u16)   [20:16] = wasm_addr (XReg)
       [25:21] = bound (XReg)  [30:26] = base (XReg)       [31] = unused
```

Address computation: `heap_base_reg + wasm_addr_reg + offset`

### PcRelOffset (i32 LE)

All branch and call offsets are **signed 32-bit** values relative to the **start** of the instruction (not the end). The target address is `instruction_address + offset`.

## P-code Semantics

All 32-bit ALU operations (`xadd32`, `xsub32`, `xshl32`, etc.) operate on the low 32 bits of source registers and **zero-extend** the result to the full 64-bit register width. This is consistent across both pulley32 and pulley64 — the ISA always uses 64-bit registers regardless of address space width.
