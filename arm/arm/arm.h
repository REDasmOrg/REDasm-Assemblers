#pragma once

#include <rdapi/rdapi.h>
#include "arm_instruction.h"

class ARMDecoder
{
    private:
        typedef bool (*Callback_ARMDecode)(const ARMInstruction*, RDInstruction*);

    public:
        static const char* regname(struct RDAssemblerPlugin*, const RDInstruction*, rd_register_id r);
        template<u32 (*Swap)(u32)> static bool decode(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction);
        static void emulate(const RDAssemblerPlugin*, RDDisassembler* disassembler, const RDInstruction* instruction);
        static bool render(const RDAssemblerPlugin*, RDRenderItemParams* rip);

    private:
        static size_t classify(const ARMInstruction* ai);
        static void renderShift(RDRenderItemParams* rip, const RDOperand* op);
        static void checkShift(RDOperand* op, u8 shift);
        static void checkStop(RDInstruction* instruction);
        static void compile(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static bool decodeDataProcessing(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeMultiply(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeMultiplyLong(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeSingleDataSwap(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeBranchAndExchange(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeHalfWordRegister(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeHalfWordImmediate(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeSingleDataTransfer(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeBlockDataTransfer(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeBranch(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeCopDataTransfer(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeCopOperator(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeCopRegTransfer(RDInstruction* instruction, const ARMInstruction* ai);
        static bool decodeSwInterrupt(RDInstruction* instruction, const ARMInstruction* ai);

    private:
        static void compileRegList(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compile2Register(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compile2Immediate(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compileRn(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compileRd(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compileRm(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compileOffset4(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compileOffset12(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
        static void compileOffset24(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop);
};
