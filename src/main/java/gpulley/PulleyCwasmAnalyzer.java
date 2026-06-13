// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Kevin Thomas

package gpulley;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/// Analyzer that discovers function boundaries and annotates host calls
/// in Pulley bytecode loaded from cwasm files.
public class PulleyCwasmAnalyzer extends AbstractAnalyzer {

    private static final int OP_CALL = 0x02;
    private static final int OP_CALL2 = 0x04;
    private static final int OP_CALL3 = 0x05;
    private static final int OP_CALL4 = 0x06;
    private static final int OP_PUSH_FRAME_SAVE = 0xaa;
    private static final int OP_PUSH_FRAME = 0xa8;
    private static final int OP_RET = 0x01;
    private static final int OP_EXTENDED = 0xdc;
    private static final int EXTOP_TRAP = 0x0000;
    private static final int EXTOP_CALL_INDIRECT_HOST = 0x0001;

    /// Constructs the Pulley cwasm analyzer.
    public PulleyCwasmAnalyzer() {
        super("Pulley Cwasm Analyzer",
                "Discovers function boundaries and annotates host calls in Pulley bytecode.",
                AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.FORMAT_ANALYSIS);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    /// Returns true if this analyzer can operate on the given program.
    @Override
    public boolean canAnalyze(Program program) {
        return "Pulley".equals(program.getLanguage().getProcessor().toString());
    }

    /// Runs the analysis pass over the Pulley bytecode.
    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        disassembleAll(program, set, monitor, log);
        int funcCount = 0;
        int hostCallCount = 0;
        InstructionIterator instIter = listing.getInstructions(set, true);
        while (instIter.hasNext() && !monitor.isCancelled()) {
            Instruction inst = instIter.next();
            Address addr = inst.getMinAddress();
            try {
                int opcode = memory.getByte(addr) & 0xff;
                if (opcode == OP_PUSH_FRAME_SAVE || opcode == OP_PUSH_FRAME) {
                    funcCount += tryCreateFunction(program, addr, log);
                }
                if (opcode == OP_CALL) {
                    funcCount += handleCallInstruction(memory, program, addr, 0, log);
                }
                if (opcode == OP_CALL2) {
                    funcCount += handleCallInstruction(memory, program, addr, 2, log);
                }
                if (opcode == OP_CALL3) {
                    funcCount += handleCallInstruction(memory, program, addr, 3, log);
                }
                if (opcode == OP_CALL4) {
                    funcCount += handleCallInstruction(memory, program, addr, 4, log);
                }
                if (opcode == OP_EXTENDED) {
                    hostCallCount += handleExtendedOp(memory, program, addr, log);
                }
            }
            catch (MemoryAccessException e) {
                continue;
            }
        }
        Msg.info(this, "Pulley analysis: discovered " + funcCount + " functions, " +
                hostCallCount + " host calls.");
        return true;
    }

    /// Disassembles the entire address set by finding each undefined gap.
    private void disassembleAll(Program program, AddressSetView set,
            TaskMonitor monitor, MessageLog log) {
        Listing listing = program.getListing();
        AddressSet undefined = new AddressSet(set);
        InstructionIterator existing = listing.getInstructions(set, true);
        while (existing.hasNext()) {
            Instruction inst = existing.next();
            undefined.delete(new AddressSet(inst.getMinAddress(), inst.getMaxAddress()));
        }
        for (AddressRange gap : undefined) {
            if (monitor.isCancelled()) break;
            DisassembleCommand cmd = new DisassembleCommand(gap.getMinAddress(), null, true);
            cmd.applyTo(program);
        }
    }

    /// Ensures disassembly at the address, then creates a function.
    private int tryCreateFunction(Program program, Address addr, MessageLog log) {
        if (program.getListing().getInstructionAt(addr) == null) {
            DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
            disCmd.applyTo(program);
        }
        if (program.getListing().getFunctionAt(addr) != null) {
            return 0;
        }
        CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
        funcCmd.applyTo(program);
        return (program.getListing().getFunctionAt(addr) != null) ? 1 : 0;
    }

    /// Handles a call instruction by resolving its target and creating a function.
    private int handleCallInstruction(Memory memory, Program program, Address addr,
            int argCount, MessageLog log) throws MemoryAccessException {
        int offsetPos = 1 + argCount;
        Address offsetAddr = addr.add(offsetPos);
        int rel = readI32LE(memory, offsetAddr);
        Address target = addr.add(rel);
        return tryCreateFunction(program, target, log);
    }

    /// Handles an extended opcode instruction.
    private int handleExtendedOp(Memory memory, Program program, Address addr,
            MessageLog log) throws MemoryAccessException {
        int extOp = readU16LE(memory, addr.add(1));
        if (extOp == EXTOP_CALL_INDIRECT_HOST) {
            int hostId = memory.getByte(addr.add(3)) & 0xff;
            program.getListing().setComment(addr,
                    CodeUnit.PLATE_COMMENT,
                    "HOST IMPORT #" + hostId);
            return 1;
        }
        if (extOp == EXTOP_TRAP) {
            program.getListing().setComment(addr,
                    CodeUnit.EOL_COMMENT, "TRAP — unreachable");
        }
        return 0;
    }

    /// Reads a signed 32-bit little-endian integer from memory.
    private int readI32LE(Memory memory, Address addr) throws MemoryAccessException {
        int b0 = memory.getByte(addr) & 0xff;
        int b1 = memory.getByte(addr.add(1)) & 0xff;
        int b2 = memory.getByte(addr.add(2)) & 0xff;
        int b3 = memory.getByte(addr.add(3)) & 0xff;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    /// Reads an unsigned 16-bit little-endian value from memory.
    private int readU16LE(Memory memory, Address addr) throws MemoryAccessException {
        int b0 = memory.getByte(addr) & 0xff;
        int b1 = memory.getByte(addr.add(1)) & 0xff;
        return b0 | (b1 << 8);
    }
}
