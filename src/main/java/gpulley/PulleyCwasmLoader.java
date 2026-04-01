// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Kevin Thomas
//
// Ghidra loader for Wasmtime cwasm (compiled WebAssembly) files.
//
// Handles two scenarios:
//   1. Standalone cwasm ELF—an ELF64 targeting pulley32-unknown-unknown-elf
//      produced by `wasmtime compile --target pulley32-...`. The .text section
//      contains raw Pulley bytecode. Symbol tables (if present) provide
//      function names and boundaries.
//
//   2. Embedded cwasm blob inside an ARM ELF—an RP2350 firmware binary where
//      the cwasm is stored as a const byte array in .rodata. The loader
//      searches for the ELF magic (0x7f "ELF") inside .rodata, validates the
//      inner ELF header, then extracts the Pulley .text section from it.
//
// In both cases the extracted Pulley bytecode is loaded into Ghidra's
// address space for disassembly with the SLEIGH spec.

package gpulley;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/// Ghidra loader that imports Pulley bytecode from cwasm ELF files.
public class PulleyCwasmLoader extends AbstractLibrarySupportLoader {

    /// ELF magic bytes: 0x7f 'E' 'L' 'F'.
    private static final byte[] ELF_MAGIC = { 0x7f, 0x45, 0x4c, 0x46 };

    /// ELF class for 64-bit (ELFCLASS64).
    private static final int ELFCLASS64 = 2;

    /// ELF data encoding for little-endian (ELFDATA2LSB).
    private static final int ELFDATA2LSB = 1;

    /// ELF machine type for EM_RISCV (Pulley cwasm uses this).
    private static final int EM_RISCV = 243;

    /// ELF OS/ABI byte identifying Pulley (0xC8 = 200).
    private static final int ELFOSABI_PULLEY = 200;

    /// ELF machine type for ARM (RP2350 firmware).
    private static final int EM_ARM = 40;

    /// ELF section type SHT_PROGBITS.
    private static final int SHT_PROGBITS = 1;

    /// ELF section type SHT_SYMTAB.
    private static final int SHT_SYMTAB = 2;

    /// ELF section type SHT_STRTAB.
    private static final int SHT_STRTAB = 3;

    /// Returns the human-readable name of this loader.
    @Override
    public String getName() {
        return "Pulley Cwasm Loader";
    }

    /// Determines if the file can be loaded as Pulley bytecode.
    /// Accepts either a Pulley ELF directly or an ARM ELF containing an
    /// embedded cwasm blob.
    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();
        byte[] header = provider.readBytes(0, Math.min(64, provider.length()));
        if (header.length < 16) {
            return loadSpecs;
        }
        if (!matchesMagic(header)) {
            return loadSpecs;
        }
        int elfClass = header[4] & 0xff;
        int osabi = header[7] & 0xff;
        int machine = readU16LE(header, 18);
        if (elfClass == ELFCLASS64 && machine == EM_RISCV && osabi == ELFOSABI_PULLEY) {
            loadSpecs.add(createPulley32LoadSpec());
            loadSpecs.add(createPulley64LoadSpec());
        }
        if (machine == EM_ARM) {
            byte[] full = provider.readBytes(0, provider.length());
            if (findEmbeddedCwasmOffset(full) >= 0) {
                loadSpecs.add(createPulley32LoadSpec());
            }
        }
        return loadSpecs;
    }

    /// Loads the Pulley bytecode into the Ghidra program.
    @Override
    protected void load(Program program, Loader.ImporterSettings settings) throws CancelledException, IOException {
        ByteProvider provider = settings.provider();
        MessageLog log = settings.log();
        TaskMonitor monitor = settings.monitor();
        FlatProgramAPI api = new FlatProgramAPI(program, monitor);
        byte[] fileBytes = provider.readBytes(0, provider.length());
        byte[] cwasmElf = extractCwasmElf(fileBytes);
        if (cwasmElf == null) {
            log.appendMsg("ERROR: Could not locate Pulley cwasm ELF data.");
            return;
        }
        loadCwasmSections(cwasmElf, api, program, log, monitor);
    }

    /// Creates a LoadSpec for the Pulley:LE:32:default language.
    private LoadSpec createPulley32LoadSpec() {
        return new LoadSpec(this, 0,
                new LanguageCompilerSpecPair("Pulley:LE:32:default", "default"), true);
    }

    /// Creates a LoadSpec for the Pulley:LE:64:default language.
    private LoadSpec createPulley64LoadSpec() {
        return new LoadSpec(this, 0,
                new LanguageCompilerSpecPair("Pulley:LE:64:default", "default"), false);
    }

    /// Checks if a byte array starts with the ELF magic bytes.
    private boolean matchesMagic(byte[] data) {
        if (data.length < 4) {
            return false;
        }
        for (int i = 0; i < 4; i++) {
            if (data[i] != ELF_MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /// Reads an unsigned 16-bit little-endian value from a byte array.
    private int readU16LE(byte[] data, int offset) {
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
    }

    /// Reads an unsigned 32-bit little-endian value from a byte array.
    private long readU32LE(byte[] data, int offset) {
        return (data[offset] & 0xffL) |
                ((data[offset + 1] & 0xffL) << 8) |
                ((data[offset + 2] & 0xffL) << 16) |
                ((data[offset + 3] & 0xffL) << 24);
    }

    /// Reads a signed 64-bit little-endian value from a byte array.
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

    /// Searches for an embedded cwasm ELF inside an ARM firmware binary.
    /// Scans for the ELF magic (0x7f ELF) and validates the inner header
    /// targets EM_NONE (Pulley) with ELFCLASS64.
    /// Returns the offset of the embedded ELF, or -1 if not found.
    private int findEmbeddedCwasmOffset(byte[] data) {
        for (int i = 0; i <= data.length - 64; i++) {
            if (data[i] == ELF_MAGIC[0] && data[i + 1] == ELF_MAGIC[1] &&
                    data[i + 2] == ELF_MAGIC[2] && data[i + 3] == ELF_MAGIC[3]) {
                if (i == 0) {
                    continue;
                }
                int cls = data[i + 4] & 0xff;
                int enc = data[i + 5] & 0xff;
                if (cls == ELFCLASS64 && enc == ELFDATA2LSB) {
                    int abi = data[i + 7] & 0xff;
                    int mach = readU16LE(data, i + 18);
                    if (mach == EM_RISCV && abi == ELFOSABI_PULLEY) {
                        return i;
                    }
                }
            }
        }
        return -1;
    }

    /// Extracts the cwasm ELF bytes. If the input is already a Pulley ELF,
    /// returns it directly. If it's an ARM ELF with an embedded cwasm blob,
    /// extracts and returns just the inner ELF.
    private byte[] extractCwasmElf(byte[] fileBytes) {
        if (fileBytes.length < 16 || !matchesMagic(fileBytes)) {
            return null;
        }
        int machine = readU16LE(fileBytes, 18);
        int elfClass = fileBytes[4] & 0xff;
        int osabi = fileBytes[7] & 0xff;
        if (elfClass == ELFCLASS64 && machine == EM_RISCV && osabi == ELFOSABI_PULLEY) {
            return fileBytes;
        }
        int offset = findEmbeddedCwasmOffset(fileBytes);
        if (offset < 0) {
            return null;
        }
        return Arrays.copyOfRange(fileBytes, offset, fileBytes.length);
    }

    /// Parses the cwasm ELF64 and loads sections into Ghidra.
    /// Extracts .text (Pulley bytecode) and applies any symbols found
    /// in the symbol table for function boundary detection.
    private void loadCwasmSections(byte[] elf, FlatProgramAPI api, Program program,
            MessageLog log, TaskMonitor monitor) throws IOException {
        if (elf.length < 64) {
            log.appendMsg("ERROR: cwasm ELF too small.");
            return;
        }
        long shOff = readU64LE(elf, 40);
        int shEntSize = readU16LE(elf, 58);
        int shNum = readU16LE(elf, 60);
        int shStrIdx = readU16LE(elf, 62);
        if (shOff + (long) shNum * shEntSize > elf.length) {
            log.appendMsg("ERROR: Section header table extends past EOF.");
            return;
        }
        long shstrOff = sectionFileOffset(elf, (int) shOff, shEntSize, shStrIdx);
        long textOff = -1;
        long textSize = 0;
        long textAddr = 0;
        long symtabOff = -1;
        long symtabSize = 0;
        int symtabEntSize = 0;
        int symtabLink = 0;
        for (int i = 0; i < shNum; i++) {
            int entOff = (int) shOff + i * shEntSize;
            long nameIdx = readU32LE(elf, entOff);
            int type = (int) readU32LE(elf, entOff + 4);
            String name = readStringAt(elf, (int) (shstrOff + nameIdx));
            long secOff = readU64LE(elf, entOff + 24);
            long secSize = readU64LE(elf, entOff + 32);
            long secAddr = readU64LE(elf, entOff + 16);
            if (".text".equals(name) && type == SHT_PROGBITS) {
                textOff = secOff;
                textSize = secSize;
                textAddr = secAddr;
            }
            if (type == SHT_SYMTAB) {
                symtabOff = secOff;
                symtabSize = secSize;
                symtabEntSize = (int) readU64LE(elf, entOff + 56);
                symtabLink = (int) readU32LE(elf, entOff + 40);
            }
        }
        if (textOff < 0) {
            log.appendMsg("WARNING: No .text section found in cwasm ELF.");
            return;
        }
        try {
            Address baseAddr = api.toAddr(textAddr);
            byte[] textBytes = Arrays.copyOfRange(elf, (int) textOff, (int) (textOff + textSize));
            MemoryBlock block = api.createMemoryBlock(".text", baseAddr, textBytes, false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);
            log.appendMsg("Loaded .text: " + textSize + " bytes at 0x" +
                    Long.toHexString(textAddr));
            if (symtabOff >= 0 && symtabEntSize > 0) {
                long strtabOff = sectionFileOffset(elf, (int) shOff, shEntSize, symtabLink);
                applySymbols(elf, symtabOff, symtabSize, symtabEntSize,
                        strtabOff, api, program, log);
            }
            api.disassemble(baseAddr);
            api.addEntryPoint(baseAddr);
        }
        catch (Exception e) {
            log.appendMsg("ERROR creating memory block: " + e.getMessage());
        }
    }

    /// Returns the file offset of the section at the given index.
    private long sectionFileOffset(byte[] elf, int shOff, int shEntSize, int index) {
        int entOff = shOff + index * shEntSize;
        return readU64LE(elf, entOff + 24);
    }

    /// Reads a null-terminated string from a byte array at the given offset.
    private String readStringAt(byte[] data, int offset) {
        if (offset < 0 || offset >= data.length) {
            return "";
        }
        int end = offset;
        while (end < data.length && data[end] != 0) {
            end++;
        }
        return new String(data, offset, end - offset);
    }

    /// Applies ELF symbols from the symbol table to the Ghidra program.
    /// Creates function labels for each STT_FUNC symbol and marks
    /// function entry points for the decompiler.
    private void applySymbols(byte[] elf, long symtabOff, long symtabSize,
            int symtabEntSize, long strtabOff, FlatProgramAPI api,
            Program program, MessageLog log) {
        int count = (int) (symtabSize / symtabEntSize);
        for (int i = 0; i < count; i++) {
            int entOff = (int) symtabOff + i * symtabEntSize;
            if (entOff + symtabEntSize > elf.length) {
                break;
            }
            long nameIdx = readU32LE(elf, entOff);
            int info = elf[entOff + 4] & 0xff;
            int type = info & 0xf;
            long value = readU64LE(elf, entOff + 8);
            long size = readU64LE(elf, entOff + 16);
            if (type != 2) {
                continue;
            }
            String name = readStringAt(elf, (int) (strtabOff + nameIdx));
            if (name.isEmpty()) {
                continue;
            }
            try {
                Address addr = api.toAddr(value);
                program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
                if (size > 0) {
                    api.createFunction(addr, name);
                }
                log.appendMsg("Symbol: " + name + " at 0x" + Long.toHexString(value) +
                        " (size=" + size + ")");
            }
            catch (Exception e) {
                log.appendMsg("WARNING: Could not create symbol '" + name + "': " +
                        e.getMessage());
            }
        }
    }

    /// Returns the list of user-configurable options for this loader.
    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean isLoadIntoProgram,
            boolean isLoadIntoNewProgram) {
        return new ArrayList<>();
    }

    /// Validates the user's option choices (no custom options currently).
    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
            List<Option> options, Program program) {
        return null;
    }
}
