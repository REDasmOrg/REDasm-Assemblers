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
        case ARM_INS_ADD: {
            RDILExpression* dst = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            RDILExpression* op1 = ARM32Lifter::liftOperand(capstone, address, insn, 1, il);

            if(insn->id == ARM_INS_ADD && arm.op_count >= 3 && ARM32Common::isPC(insn, 1) && (arm.operands[2].type == ARM_OP_IMM))
                e = RDILFunction_COPY(il, dst, RDILFunction_CNST(il, sizeof(u32), ARM32Common::pc(capstone, insn) + arm.operands[2].imm));
            else if(arm.op_count == 2)
                e = RDILFunction_COPY(il, dst, RDILFunction_ADD(il, dst, op1));
            else {
                auto* op2 = ARM32Lifter::liftOperand(capstone, address, insn, 2, il);
                e = RDILFunction_COPY(il, dst, RDILFunction_ADD(il, op1, op2));
            }

            break;
        }

        case ARM_INS_B: {
            auto* op = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            e = RDILFunction_GOTO(il, op);
            break;
        }

        case ARM_INS_BLX: {
            auto* op = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            e = RDILFunction_CALL(il, op);
            break;
        }

        case ARM_INS_ASR: {
            auto* op0 = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            auto* op1 = ARM32Lifter::liftOperand(capstone, address, insn, 1, il);
            auto* op2 = ARM32Lifter::liftOperand(capstone, address, insn, 2, il);
            e = RDILFunction_COPY(il, op0, RDILFunction_ASR(il, op1, op2));
            break;
        }

        case ARM_INS_LDR: {
            auto* op0 = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            auto* op1 = ARM32Lifter::liftOperand(capstone, address, insn, 1, il);
            e = RDILFunction_COPY(il, op0, op1);
            break;
        }

        case ARM_INS_STR: {
            auto* op0 = ARM32Lifter::liftOperand(capstone, address, insn, 0, il);
            auto* op1 = ARM32Lifter::liftOperand(capstone, address, insn, 1, il);
            e = RDILFunction_COPY(il, op1, op0);
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

            if(ARM32Common::isMemPC(op.mem)) disp = RDILFunction_CNST(il, sz, ARM32Common::pc(capstone, insn) + op.mem.disp);
            else if(op.mem.disp) disp = RDILFunction_CNST(il, sz, op.mem.disp);

            if(base && index) e = RDILFunction_MUL(il, base, index);
            else if(base) e = base;

            if(disp && e) e = op.mem.disp > 0 ? RDILFunction_ADD(il, e, disp) : RDILFunction_SUB(il, e, disp);
            else if(disp) e = disp;

            if(!e) e = RDILFunction_UNKNOWN(il);
            e = RDILFunction_MEM(il, e);
            break;
        }

        default: e = RDILFunction_UNKNOWN(il); break;
    }

    return e;
}
