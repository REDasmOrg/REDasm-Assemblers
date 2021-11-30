#pragma once

#include "../capstone.h"

class ARM32Lifter
{
    public:
        ARM32Lifter() = delete;
        static void lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il);

    private:
        static RDILExpression* liftOperand(const Capstone* capstone, rd_address address, const cs_insn* insn, size_t idx, const RDILFunction* il);
};

