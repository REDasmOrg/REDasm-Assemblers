#include "arm32_lifter.h"
#include "../capstone.h"
#include "common.h"
#include <climits>

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
        case ARM_INS_BLX: {
            auto* op = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            e = RDILFunction_CALL(il, op);
            break;
        }

        case ARM_INS_LDR: {
            auto* op0 = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            auto* op1 = ARM32Lifter::liftOperand(capstone, address, insn, 1, il);
            e = RDILFunction_COPY(il, op0, op1);
            break;
        }

        case ARM_INS_MOV: {
            auto* op0 = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            auto* op1 = ARM32Lifter::liftOperand(capstone, address, insn, 1, il);
            e = RDILFunction_COPY(il, op0, op1);
            break;
        }

        default:
            e = RDILFunction_UNKNOWN(il);
            break;
    }

    RDILFunction_Append(il, e);
}

RDILExpression* ARM32Lifter::liftOperand(const Capstone* capstone, rd_address address, const cs_insn* insn, size_t idx, const RDILFunction* il)
{
    const size_t sz = sizeof(u32) / CHAR_BIT;
    const auto& op = insn->detail->arm.operands[idx];
    RDILExpression* e = nullptr;

    switch(op.type)
    {
        case ARM_OP_REG: e = RDILFunction_REG(il, sz, capstone->regName(op.reg)); break;
        case ARM_OP_IMM: e = RDILFunction_CNST(il, sz, op.imm); break;

        case ARM_OP_MEM: {
            RDILExpression *base = nullptr, *index = nullptr, *disp = nullptr;

            if((op.mem.base != ARM_REG_INVALID) && (op.mem.base != ARM_REG_PC)) base = RDILFunction_REG(il, sz, capstone->regName(op.mem.base));
            if(op.mem.index != ARM_REG_INVALID) index = RDILFunction_REG(il, sz, capstone->regName(op.mem.index));

            if(ARM32Common::isMemPC(op.mem)) disp = RDILFunction_CNST(il, sz, ARM32Common::pc(address) + op.mem.disp);
            else disp = RDILFunction_CNST(il, sz, op.mem.disp);

            if(base && index) e = RDILFunction_MUL(il, base, index);
            else if(base) e = base;

            if(disp && e) e = RDILFunction_ADD(il, e, disp);
            else if(disp) e = disp;

            if(!e) e = RDILFunction_UNKNOWN(il);
            e = RDILFunction_MEM(il, e);
            break;
        }

        default: e = RDILFunction_UNKNOWN(il); break;
    }

    return e;
}
