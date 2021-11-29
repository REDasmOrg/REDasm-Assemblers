#include "lifter.h"
#include "../capstone.h"

void ARM32Lifter::lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il)
{
    const cs_insn* insn = capstone->decode(address, view);

    if(!insn)
    {
        RDILFunction_Append(il, RDILFunction_UNKNOWN(il));
        return;
    }

    const auto& arm = insn->detail->arm;
    RDILExpression* e = nullptr;

    switch(insn->id)
    {
        default:
            e = RDILFunction_UNKNOWN(il);
            break;
    }

    RDILFunction_Append(il, e);
}
