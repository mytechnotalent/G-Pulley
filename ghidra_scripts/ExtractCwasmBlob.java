// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Kevin Thomas
//
// Ghidra script: Extract a cwasm (compiled WebAssembly) blob from an
// already-loaded ARM ELF binary (e.g., RP2350 firmware).
//
// Usage:
//   1. Open the ARM ELF firmware in Ghidra normally (with the ARM processor).
//   2. Run this script from Script Manager.
//   3. The script scans all memory blocks for ELF64 magic with EM_NONE,
//      extracts the embedded cwasm ELF, and saves it to a file.
//   4. The saved file can then be imported into a separate Ghidra project
//      using the "Pulley Cwasm Loader" for full Pulley disassembly.
//
// This is useful when you want to analyze the ARM firmware and the
// Pulley bytecode in separate Ghidra windows side-by-side.
//
// @category Analysis
// @keybinding
// @menupath Tools.Extract Cwasm Blob
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.Arrays;

/// Script that extracts an embedded cwasm ELF from ARM firmware.
public class ExtractCwasmBlob extends GhidraScript {

    /// ELF magic bytes: 0x7f 'E' 'L' 'F'.
    private static final byte[] ELF_MAGIC = { 0x7f, 0x45, 0x4c, 0x46 };

    /// ELF class for 64-bit (ELFCLASS64).
    private static final int ELFCLASS64 = 2;

    /// ELF data encoding for little-endian (ELFDATA2LSB).
    private static final int ELFDATA2LSB = 1;

    /// ELF machine type for EM_NONE (Pulley uses this).
    private static final int EM_NONE = 0;

    /// Runs the cwasm extraction script.
    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        println("Scanning " + blocks.length + " memory blocks for embedded cwasm ELF...");
        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) {
                continue;
            }
            long size = block.getSize();
            if (size < 64) {
                continue;
            }
            byte[] data = new byte[(int) size];
            block.getBytes(block.getStart(), data);
            int offset = findCwasmElf(data);
            if (offset < 0) {
                continue;
            }
            println("Found cwasm ELF at offset 0x" + Integer.toHexString(offset) +
                    " in block '" + block.getName() + "'");
            long elfSize = determineCwasmElfSize(data, offset);
            if (elfSize <= 0) {
                println("WARNING: Could not determine cwasm ELF size, extracting to end of block.");
                elfSize = size - offset;
            }
            byte[] cwasmBytes = Arrays.copyOfRange(data, offset, offset + (int) elfSize);
            File outFile = askFile("Save cwasm ELF as", "Save");
            if (outFile != null) {
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    fos.write(cwasmBytes);
                }
                println("Saved " + cwasmBytes.length + " bytes to " + outFile.getAbsolutePath());
                println("Import this file in Ghidra with the 'Pulley Cwasm Loader'.");
            }
            return;
        }
        println("No embedded cwasm ELF found in any memory block.");
    }

    /// Searches a byte array for an embedded ELF64 + EM_NONE header.
    /// Returns the offset, or -1 if not found.
    private int findCwasmElf(byte[] data) {
        for (int i = 0; i <= data.length - 64; i++) {
            if (data[i] != ELF_MAGIC[0] || data[i + 1] != ELF_MAGIC[1] ||
                    data[i + 2] != ELF_MAGIC[2] || data[i + 3] != ELF_MAGIC[3]) {
                continue;
            }
            int cls = data[i + 4] & 0xff;
            int enc = data[i + 5] & 0xff;
            if (cls != ELFCLASS64 || enc != ELFDATA2LSB) {
                continue;
            }
            int mach = readU16LE(data, i + 18);
            if (mach == EM_NONE) {
                return i;
            }
        }
        return -1;
    }

    /// Determines the total size of the ELF64 file at the given offset
    /// by reading the section header table position and computing the
    /// maximum extent. Returns -1 on error.
    private long determineCwasmElfSize(byte[] data, int elfStart) {
        if (elfStart + 64 > data.length) {
            return -1;
        }
        long shOff = readU64LE(data, elfStart + 40);
        int shEntSize = readU16LE(data, elfStart + 58);
        int shNum = readU16LE(data, elfStart + 60);
        long shEnd = shOff + (long) shNum * shEntSize;
        long maxExtent = shEnd;
        for (int i = 0; i < shNum; i++) {
            int entOff = elfStart + (int) shOff + i * shEntSize;
            if (entOff + shEntSize > data.length) {
                break;
            }
            long secOff = readU64LE(data, entOff + 24);
            long secSize = readU64LE(data, entOff + 32);
            long secEnd = secOff + secSize;
            if (secEnd > maxExtent) {
                maxExtent = secEnd;
            }
        }
        return maxExtent;
    }

    /// Reads an unsigned 16-bit little-endian value from a byte array.
    private int readU16LE(byte[] data, int offset) {
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
    }

    /// Reads an unsigned 64-bit little-endian value from a byte array.
    private long readU64LE(byte[] data, int offset) {
        return (data[offset] & 0xffL) |
                ((data[offset + 1] & 0xffL) << 8) |
                ((data[offset + 2] & 0xffL) << 16) |
                ((data[offset + 3] & 0xffL) << 24) |
                ((data[offset + 4] & 0xffL) << 32) |
                ((data[offset + 5] & 0xffL) << 40) |
                ((data[offset + 6] & 0xffL) << 48) |
                ((data[offset + 7] & 0xffL) << 56);
    }
}
