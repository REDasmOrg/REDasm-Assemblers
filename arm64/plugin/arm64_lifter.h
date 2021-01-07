#pragma once

#include <rdapi/rdapi.h>
#include <capstone/capstone.h>

class ARM64Lifter
{
    public:
        ARM64Lifter() = delete;
        static void lift(RDContext* ctx, rd_address address, const RDBufferView* view, RDILFunction* il);

    private:
        static RDILExpression* liftConditionalJump(csh h, const cs_insn* insn, RDILExpression* cond, RDILFunction* il);
        static RDILExpression* liftMath(csh h, unsigned int id, const cs_arm64& arm64, RDILFunction* il);
        static RDILExpression* liftOperand(csh h, const cs_arm64_op& op, RDILFunction* il);
};

