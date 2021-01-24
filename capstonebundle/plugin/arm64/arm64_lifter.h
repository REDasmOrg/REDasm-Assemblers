#pragma once

#include <rdapi/rdapi.h>
#include "../capstone.h"

class ARM64Lifter: public CapstoneLifter
{
    public:
        ARM64Lifter(RDContext* ctx);
        void lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il) override;

    private:
        RDILExpression* liftConditionalJump(const Capstone* capstone, const cs_insn* insn, RDILExpression* cond, RDILFunction* il) const;
        RDILExpression* liftMath(const Capstone* capstone, unsigned int id, const cs_arm64& arm64, RDILFunction* il) const;
        RDILExpression* liftOperand(const Capstone* capstone, const cs_arm64_op& op, RDILFunction* il) const;
};

