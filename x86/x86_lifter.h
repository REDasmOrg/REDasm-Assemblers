#pragma once

#include "zydiscommon.h"

class X86Lifter: public ZydisCommon
{
    public:
        X86Lifter() = delete;
        static void lift(const RDAssemblerPlugin* plugin, ZydisDecoder decoder, rd_address address, const RDBufferView* view, RDILFunction* il);

    private:
        static void liftJump(const ZydisDecodedInstruction* zinstr, rd_address address, RDILFunction* il);
        static RDILExpression* liftOperand(rd_address address, const ZydisDecodedInstruction* zinstr, size_t idx, const RDILFunction* il);
        static bool needsCalcAddress(const ZydisDecodedInstruction* zinstr);
};

