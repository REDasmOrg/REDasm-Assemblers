#include "arm64_lifter.h"
#include "arm64.h"

ARM64Lifter::ARM64Lifter(RDContext* ctx): CapstoneLifter(ctx) { }

void ARM64Lifter::lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il)
{
    const cs_insn* insn = capstone->decode(address, view);

    if(!insn)
    {
        RDILFunction_Append(il, RDILFunction_UNKNOWN(il));
        return;
    }

    const auto& arm64 = insn->detail->arm64;

    RDILExpression* e = nullptr;

    switch(insn->id)
    {
        case ARM64_INS_ADD:
        case ARM64_INS_SUB:
        case ARM64_INS_AND:
        case ARM64_INS_ORR:
        case ARM64_INS_EOR:
            e = ARM64Lifter::liftMath(capstone, insn->id, arm64, il);
            break;

        case ARM64_INS_CBNZ: {
            auto* cond = RDILFunction_NE(il, ARM64Lifter::liftOperand(capstone, arm64.operands[0], il), RDILFunction_CNST(il, sizeof(u64), 0));
            e = ARM64Lifter::liftConditionalJump(capstone, insn, cond, il);
            break;
        }

        case ARM64_INS_CBZ: {
            auto* cond = RDILFunction_EQ(il, ARM64Lifter::liftOperand(capstone, arm64.operands[0], il), RDILFunction_CNST(il, sizeof(u64), 0));
            e = ARM64Lifter::liftConditionalJump(capstone, insn, cond, il);
            break;
        }

        case ARM64_INS_MOV:
        case ARM64_INS_MOVZ: {
            auto* dst = ARM64Lifter::liftOperand(capstone, arm64.operands[0], il);
            auto* src = ARM64Lifter::liftOperand(capstone, arm64.operands[1], il);
            e = RDILFunction_COPY(il, dst, src);
            break;
        }

        case ARM64_INS_B:
        case ARM64_INS_BR:
            e = RDILFunction_GOTO(il, ARM64Lifter::liftOperand(capstone, arm64.operands[0], il));
            break;

        case ARM64_INS_BL:
        case ARM64_INS_BLR:
            e = RDILFunction_CALL(il, ARM64Lifter::liftOperand(capstone, arm64.operands[0], il));
            break;

        default:
            e = RDILFunction_UNKNOWN(il);
            break;
    }

    RDILFunction_Append(il, e);
}

RDILExpression* ARM64Lifter::liftOperand(const Capstone* capstone, const cs_arm64_op& op, RDILFunction* il) const
{
    switch(op.type)
    {
        case ARM64_OP_REG: return RDILFunction_REG(il, sizeof(u64), capstone->regName(op.reg));
        case ARM64_OP_IMM: return RDILFunction_CNST(il, sizeof(u64), static_cast<u64>(op.imm));
        case ARM64_OP_MEM: break;
        default: break;
    }

    return RDILFunction_UNKNOWN(il);
}

RDILExpression* ARM64Lifter::liftConditionalJump(const Capstone* capstone, const cs_insn* insn, RDILExpression* cond, RDILFunction* il) const
{
    auto* t = RDILFunction_GOTO(il, ARM64Lifter::liftOperand(capstone, insn->detail->arm64.operands[1], il));
    auto* f = RDILFunction_GOTO(il, RDILFunction_CNST(il, sizeof(u64), insn->address + insn->size));
    return RDILFunction_IF(il, cond, t, f);
}

RDILExpression* ARM64Lifter::liftMath(const Capstone* capstone, unsigned int id, const cs_arm64& arm64, RDILFunction* il) const
{
    if(arm64.op_count != 3) return RDILFunction_UNKNOWN(il);

    auto* dst = ARM64Lifter::liftOperand(capstone, arm64.operands[0], il);
    auto* src1 = ARM64Lifter::liftOperand(capstone, arm64.operands[1], il);
    auto* src2 = ARM64Lifter::liftOperand(capstone, arm64.operands[2], il);

    RDILExpression* e = nullptr;

    switch(id)
    {
        case ARM64_INS_ADD: e = RDILFunction_ADD(il, src1, src2); break;
        case ARM64_INS_SUB: e = RDILFunction_SUB(il, src1, src2); break;
        case ARM64_INS_AND: e = RDILFunction_AND(il, src1, src2); break;
        case ARM64_INS_ORR: e = RDILFunction_OR(il, src1, src2);  break;
        case ARM64_INS_EOR: e = RDILFunction_XOR(il, src1, src2); break;
        default: break;
    }

    if(!e) return RDILFunction_UNKNOWN(il);
    return RDILFunction_COPY(il, dst, e);
}
