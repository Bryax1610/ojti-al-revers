// Read-only, deliberately bounded instruction checks. No inferred type is repaired.
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

public final class ReaGhidraPrototypeDiagnostics {
    // Shared epilogues and call/return observations are probes, not CFG recovery.
    private static final int EPILOGUE_INSTRUCTIONS = 16;

    public static JsonObject inspect(Program program, Function function,
            FunctionPrototype prototype, TaskMonitor monitor,
            java.util.function.Function<Address, String> addressText) throws Exception {
        JsonObject result = new JsonObject();
        JsonArray diagnostics = new JsonArray();
        JsonArray limitations = new JsonArray();
        result.add("diagnostics", diagnostics);
        result.add("limitations", limitations);
        if (!program.getLanguage().getProcessor().toString().equals("x86") ||
                program.getLanguage().getLanguageDescription().getSize() != 32) {
            limitations.add("Instruction/prototype checks support x86-32 only; consistency on this target remains unknown.");
            return result;
        }
        limitations.add("Stack-read checks cover the straight-line entry prefix before its first architectural or raw p-code control transfer. Calls, joins, aliases and dynamic stack adjustments are not propagated; absence of a diagnostic does not establish prototype consistency.");
        limitations.add("Return cleanup is compared with recovered stack-storage extent including compiler-model slot padding, not a source argument count. Custom or unknown slot allocation is not classified as a cleanup conflict. Shared epilogues are followed for at most 16 simple instructions without expanding owned-body ranges; indirect flows, tail calls and longer paths remain unknown.");
        limitations.add("Return-register forwarding is a bounded EAX observation, not proof of a source return type. x87 instructions preserve inputs and operations, not a complete expression, missing multiplier, signedness or compiler identity.");
        List<Varnode> parameters = new ArrayList<>();
        List<long[]> slots = new ArrayList<>();
        String modelName = prototype.getModelName();
        PrototypeModel model = modelName == null ? null : program.getCompilerSpec().getCallingConvention(modelName);
        PrototypeModel allocationModel = model;
        boolean knownAllocation = !function.hasCustomVariableStorage() && allocationModel != null &&
            !allocationModel.isMerged() && !allocationModel.isProgramExtension() &&
            allocationModel.getStackshift() == 4 && Long.valueOf(4).equals(allocationModel.getStackParameterOffset()) &&
            allocationModel.getStackParameterAlignment() == 4;
        long stackEnd = 4;
        for (int index = 0; index < prototype.getNumParams(); index++) {
            if (prototype.getParam(index) == null) continue;
            for (Varnode node : prototype.getParam(index).getStorage().getVarnodes()) {
                if (!node.getAddress().getAddressSpace().isStackSpace()) continue;
                if (prototype.getParam(index).getDataType().getAlignment() > 4 ||
                    prototype.getParam(index).getDataType().getAlignedLength() > ((node.getSize() + 3) / 4) * 4)
                    knownAllocation = false;
                parameters.add(node);
                long end = node.getOffset() + node.getSize();
                if (node.getOffset() < 4 || node.getOffset() % 4 != 0) knownAllocation = false;
                slots.add(new long[] { node.getOffset(), 4 + ((end - 4 + 3) / 4) * 4 });
                stackEnd = Math.max(stackEnd, end);
            }
        }
        if (knownAllocation) stackEnd = 4 + ((stackEnd - 4 + 3) / 4) * 4;
        if (!knownAllocation) limitations.add("Compiler-model x86 stack-slot allocation could not be established; padding reads and return cleanup remain observations or unknowns.");
        boolean calleeCleanup = model != null && !model.isProgramExtension() && !model.isMerged() &&
            model.getExtrapop() == PrototypeModel.UNKNOWN_EXTRAPOP;
        String claim = "The recovered prototype has " + prototype.getNumParams() +
            " parameters and " + (stackEnd - 4) + " bytes of recovered x86 stack-argument extent" +
            (knownAllocation ? " including compiler-model slot padding" : " with allocation unknown") +
            " (calling convention " + (modelName == null ? "unknown" : modelName) + ").";
        Register esp = program.getRegister("ESP");
        Register eax = program.getRegister("EAX");
        if (esp == null || eax == null) {
            limitations.add("Required ESP/EAX register identities are unavailable; instruction checks were not performed.");
            return result;
        }
        Map<Varnode, Long> offsets = new HashMap<>();
        offsets.put(new Varnode(esp.getAddress(), 4), 0L);
        JsonArray x87 = new JsonArray();
        List<long[]> writtenStack = new ArrayList<>();
        boolean unknownStore = false;
        Set<Address> visited = new HashSet<>();
        Instruction instruction = program.getListing().getInstructionAt(function.getEntryPoint());
        while (instruction != null && function.getBody().contains(instruction.getAddress()) &&
                visited.add(instruction.getAddress())) {
            monitor.checkCancelled();
            if (instruction.getFlowType().isCall()) {
                if (!x87.isEmpty()) x87.add(evidence("call-site", instruction,
                    "Call following x87 operations: " + instruction, addressText));
                break;
            }
            if (instruction.getFlowType().isJump() || isReturn(instruction) || instruction.getFlowType().isTerminal()) break;
            boolean internalFlow = false;
            for (PcodeOp operation : instruction.getPcode())
                if (operation.getOpcode() == PcodeOp.BRANCH || operation.getOpcode() == PcodeOp.CBRANCH ||
                    operation.getOpcode() == PcodeOp.BRANCHIND || operation.getOpcode() == PcodeOp.CALL ||
                    operation.getOpcode() == PcodeOp.CALLIND || operation.getOpcode() == PcodeOp.CALLOTHER) internalFlow = true;
            if (internalFlow) {
                limitations.add("Raw p-code control flow at " + addressText.apply(instruction.getAddress()) +
                    " or an unsupported user-op makes subsequent stack offsets or memory effects ambiguous; entry stack-read propagation stopped.");
                break;
            }
            offsets.keySet().removeIf(Varnode::isUnique);
            if (instruction.getMnemonicString().toUpperCase(Locale.ROOT).startsWith("F"))
                x87.add(evidence("instruction", instruction, "Observed x87 instruction: " + instruction, addressText));
            for (PcodeOp operation : instruction.getPcode()) {
                if (operation.getOpcode() == PcodeOp.STORE) {
                    Long offset = offsets.get(operation.getInput(1));
                    if (offset == null) {
                        if (!unknownStore) limitations.add("A store with unresolved aliasing at " + addressText.apply(instruction.getAddress()) +
                            " prevents subsequent stack reads from establishing unmodified entry inputs.");
                        unknownStore = true;
                    } else writtenStack.add(new long[] { offset, offset + operation.getInput(2).getSize() });
                }
                if (operation.getOpcode() == PcodeOp.LOAD) {
                    Long offset = offsets.get(operation.getInput(1));
                    int size = operation.getOutput().getSize();
                    if (offset != null && offset >= 4 && !covered(parameters, offset, size) &&
                            !(knownAllocation && coveredSlots(slots, offset, size))) {
                        if (unknownStore || overlaps(writtenStack, offset, size)) {
                            limitations.add("Stack read at " + addressText.apply(instruction.getAddress()) +
                                " may contain data written by this entry prefix; an omitted entry input was not established.");
                        } else {
                            JsonArray facts = new JsonArray();
                            facts.add(evidence("stack-read", instruction,
                                "Raw instruction p-code reads " + size + " bytes at entry ESP + " + offset +
                                ", outside recovered parameter storage" + (knownAllocation ? " and its compiler-model slots." : "."), addressText));
                            boolean conflict = !prototype.isVarArg() && (knownAllocation || parameters.isEmpty());
                            diagnostics.add(diagnostic("stack-parameter-read", conflict ? "conflict" : "observation", claim, facts,
                                "The read may reflect an omitted, hidden or variadic input, ABI padding, a custom ABI or stack data; its source type and source parameter count remain unknown."));
                        }
                    }
                }
                Varnode output = operation.getOutput();
                if (output == null) continue;
                Long value = propagatedOffset(operation, offsets);
                offsets.keySet().removeIf(node -> node.intersects(output));
                if (value != null) offsets.put(output, value);
            }
            Address next = instruction.getFallThrough();
            instruction = next == null ? null : program.getListing().getInstructionAt(next);
        }
        if (!x87.isEmpty()) diagnostics.add(diagnostic("x87-expression", "observation", claim, x87,
            "The x87 entry inputs and listed operations do not establish a complete expression or the semantics of a following call. Missing factors, conversion type, signedness and compiler identity remain unknown."));

        Set<Address> reportedReturns = new HashSet<>();
        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction item = instructions.next();
            if (isReturn(item) && knownAllocation) cleanupDiagnostic(item, null, stackEnd - 4, prototype, calleeCleanup, claim,
                diagnostics, reportedReturns, addressText);
            if (item.getFlowType().isJump() && !item.getFlowType().isConditional() && !item.getFlowType().isComputed()) {
                Address[] targets = item.getFlows();
                if (targets.length == 1 && !function.getBody().contains(targets[0])) {
                    Instruction returned = epilogueReturn(program, function, targets[0], eax, false, monitor);
                    if (returned != null) {
                        if (knownAllocation) cleanupDiagnostic(returned, item, stackEnd - 4, prototype, calleeCleanup, claim,
                            diagnostics, reportedReturns, addressText);
                    }
                    else limitations.add("Shared epilogue or tail-call target from " + addressText.apply(item.getAddress()) +
                        " could not be established within the bounded cleanup check.");
                }
            }
            String returnType = prototype.getReturnType().getDisplayName();
            if (!item.getFlowType().isCall() || !(returnType.equals("void") || returnType.startsWith("undefined"))) continue;
            Instruction returned = epilogueReturn(program, function, item.getFallThrough(), eax, true, monitor);
            if (returned == null) continue;
            JsonArray facts = new JsonArray();
            facts.add(evidence("call-site", item, "Call followed by a simple epilogue with no raw p-code write to EAX.", addressText));
            facts.add(evidence("return", returned, "Return reached with the call's EAX register unmodified by the checked epilogue.", addressText));
            ReferenceIterator callers = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
            while (callers.hasNext()) {
                monitor.checkCancelled();
                Reference reference = callers.next();
                if (!reference.getReferenceType().isCall()) continue;
                Instruction caller = program.getListing().getInstructionAt(reference.getFromAddress());
                if (caller == null || caller.getFallThrough() == null) continue;
                Instruction use = program.getListing().getInstructionAt(caller.getFallThrough());
                if (use != null && readsRegister(use, eax)) facts.add(evidence("call-site", use,
                    "The immediate caller continuation reads EAX in raw p-code; return intent is not established.", addressText));
            }
            diagnostics.add(diagnostic("return-register-forwarding", "observation",
                "The recovered return type is " + returnType + ".", facts,
                "EAX may be an incidental live register. Callee return semantics, caller data flow and the source return type require corroboration."));
        }
        return result;
    }

    private static boolean covered(List<Varnode> parameters, long offset, int size) {
        for (int index = 0; index < size; index++) {
            long byteOffset = offset + index;
            if (parameters.stream().noneMatch(node -> byteOffset >= node.getOffset() &&
                    byteOffset < node.getOffset() + node.getSize())) return false;
        }
        return true;
    }

    private static boolean coveredSlots(List<long[]> slots, long offset, int size) {
        for (int index = 0; index < size; index++) {
            long byteOffset = offset + index;
            if (slots.stream().noneMatch(slot -> byteOffset >= slot[0] && byteOffset < slot[1])) return false;
        }
        return true;
    }

    private static boolean overlaps(List<long[]> ranges, long offset, int size) {
        return ranges.stream().anyMatch(range -> offset < range[1] && offset + size > range[0]);
    }

    private static Long propagatedOffset(PcodeOp operation, Map<Varnode, Long> offsets) {
        if (operation.getOpcode() == PcodeOp.COPY) return offsets.get(operation.getInput(0));
        if (operation.getOpcode() != PcodeOp.INT_ADD && operation.getOpcode() != PcodeOp.INT_SUB) return null;
        Long left = offsets.get(operation.getInput(0));
        Varnode right = operation.getInput(1);
        if (left != null && right.isConstant()) {
            long constant = signedConstant(right);
            return operation.getOpcode() == PcodeOp.INT_ADD ? left + constant : left - constant;
        }
        if (operation.getOpcode() == PcodeOp.INT_ADD && operation.getInput(0).isConstant()) {
            Long rightOffset = offsets.get(right);
            if (rightOffset != null) return rightOffset + signedConstant(operation.getInput(0));
        }
        return null;
    }

    private static long signedConstant(Varnode constant) {
        int shift = 64 - constant.getSize() * 8;
        return shift > 0 ? (constant.getOffset() << shift) >> shift : constant.getOffset();
    }

    private static boolean isReturn(Instruction instruction) {
        for (PcodeOp operation : instruction.getPcode()) if (operation.getOpcode() == PcodeOp.RETURN) return true;
        return false;
    }

    private static boolean writesRegister(Instruction instruction, Register register) {
        Varnode node = new Varnode(register.getAddress(), register.getMinimumByteSize());
        for (PcodeOp operation : instruction.getPcode())
            if (operation.getOpcode() == PcodeOp.CALLOTHER || operation.getOutput() != null && node.intersects(operation.getOutput())) return true;
        return false;
    }

    private static boolean readsRegister(Instruction instruction, Register register) {
        Varnode node = new Varnode(register.getAddress(), register.getMinimumByteSize());
        for (PcodeOp operation : instruction.getPcode()) {
            // Self-XOR/SUB and subtraction flags are independent of the incoming value.
            // Their register writes still kill it before later flag p-code reads the result.
            boolean independent = (operation.getOpcode() == PcodeOp.INT_XOR || operation.getOpcode() == PcodeOp.INT_SUB ||
                operation.getOpcode() == PcodeOp.INT_LESS || operation.getOpcode() == PcodeOp.INT_SBORROW) &&
                operation.getInput(0).equals(operation.getInput(1));
            if (!independent)
                for (int i = 0; i < operation.getNumInputs(); i++) if (node.intersects(operation.getInput(i))) return true;
            if (operation.getOutput() != null && node.intersects(operation.getOutput())) return false;
        }
        return false;
    }

    private static Instruction epilogueReturn(Program program, Function function, Address start,
            Register eax, boolean preserveEax, TaskMonitor monitor) throws Exception {
        Set<Address> visited = new HashSet<>();
        Address address = start;
        for (int count = 0; count < EPILOGUE_INSTRUCTIONS && address != null && visited.add(address); count++) {
            monitor.checkCancelled();
            Function entry = program.getFunctionManager().getFunctionAt(address);
            if (entry != null && !entry.equals(function)) return null; // A separate entry can be a tail call.
            Instruction item = program.getListing().getInstructionAt(address);
            if (item == null) return null;
            if (isReturn(item)) return item;
            if (preserveEax && writesRegister(item, eax)) return null;
            if (item.getFlowType().isJump() && !item.getFlowType().isConditional() && !item.getFlowType().isComputed()) {
                Address[] targets = item.getFlows();
                if (targets.length != 1) return null;
                address = targets[0];
                continue;
            }
            if (item.getFlowType().isCall() || item.getFlowType().isJump() || item.getFlowType().isTerminal()) return null;
            String mnemonic = item.getMnemonicString().toUpperCase(Locale.ROOT);
            if (!Set.of("POP", "LEAVE", "NOP").contains(mnemonic) &&
                !(Set.of("ADD", "MOV").contains(mnemonic) && item.getRegister(0) != null &&
                  item.getRegister(0).getName().equals("ESP"))) return null;
            address = item.getFallThrough();
        }
        return null;
    }

    private static void cleanupDiagnostic(Instruction returned, Instruction branch, long extent,
            FunctionPrototype prototype, boolean calleeCleanup, String claim, JsonArray diagnostics, Set<Address> reported,
            java.util.function.Function<Address, String> addressText) {
        if (!reported.add(returned.getAddress()) || !returned.getMnemonicString().equalsIgnoreCase("RET")) return;
        long cleanup = returned.getNumOperands() == 0 || returned.getScalar(0) == null ? 0 : returned.getScalar(0).getUnsignedValue();
        // A plain cdecl RET is expected even with stack inputs. Variadic cleanup is not comparable.
        if (prototype.isVarArg() || cleanup == extent || cleanup == 0 && !calleeCleanup) return;
        JsonArray facts = new JsonArray();
        if (branch != null) facts.add(evidence("branch", branch, "Direct branch to a shared epilogue outside the owned body; no body range was added.", addressText));
        facts.add(evidence("return", returned, "RET explicitly cleans up " + cleanup + " bytes, compared with " + extent + " recovered stack-argument bytes.", addressText));
        diagnostics.add(diagnostic("stack-cleanup", "conflict", claim, facts,
            "Hidden parameters, stack padding, custom calling conventions and incomplete parameter recovery remain possible. Cleanup bytes do not prove a source argument count."));
    }

    private static JsonObject evidence(String kind, Instruction instruction, String detail,
            java.util.function.Function<Address, String> addressText) {
        JsonObject result = new JsonObject();
        result.addProperty("kind", kind);
        result.addProperty("address", addressText.apply(instruction.getAddress()));
        result.addProperty("detail", detail);
        return result;
    }

    private static JsonObject diagnostic(String kind, String classification, String claim,
            JsonArray evidence, String unknown) {
        JsonObject result = new JsonObject();
        result.addProperty("kind", kind);
        result.addProperty("classification", classification);
        result.addProperty("inferred_claim", claim);
        result.add("evidence", evidence);
        JsonArray unknowns = new JsonArray();
        unknowns.add(unknown);
        result.add("residual_unknowns", unknowns);
        return result;
    }
}
