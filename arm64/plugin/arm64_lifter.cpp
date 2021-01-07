#include "arm64_lifter.h"
#include "arm64.h"

void ARM64Lifter::lift(RDContext* ctx, rd_address address, const RDBufferView* view, RDILFunction* il)
{
    csh h = ARM64::handle(ctx);
    if(!h) return;

    if(!ARM64::decode(h, address, view) || !ARM64::instruction())
    {
        RDILFunction_Append(il, RDILFunction_UNKNOWN(il));
        return;
    }

    const cs_insn* insn = ARM64::instruction();
    const auto& arm64 = insn->detail->arm64;

    RDILExpression* e = nullptr;

    switch(insn->id)
    {
        case ARM64_INS_ADD:
        case ARM64_INS_SUB:
        case ARM64_INS_AND:
        case ARM64_INS_ORR:
        case ARM64_INS_EOR:
            e = ARM64Lifter::liftMath(h, insn->id, arm64, il);
            break;

        case ARM64_INS_CBNZ: {
            auto* cond = RDILFunction_NE(il, ARM64Lifter::liftOperand(h, arm64.operands[0], il), RDILFunction_CNST(il, sizeof(u64), 0));
            e = ARM64Lifter::liftConditionalJump(h, insn, cond, il);
            break;
        }

        case ARM64_INS_CBZ: {
            auto* cond = RDILFunction_EQ(il, ARM64Lifter::liftOperand(h, arm64.operands[0], il), RDILFunction_CNST(il, sizeof(u64), 0));
            e = ARM64Lifter::liftConditionalJump(h, insn, cond, il);
            break;
        }

        case ARM64_INS_MOV:
        case ARM64_INS_MOVZ: {
            auto* dst = ARM64Lifter::liftOperand(h, arm64.operands[0], il);
            auto* src = ARM64Lifter::liftOperand(h, arm64.operands[1], il);
            e = RDILFunction_COPY(il, dst, src);
            break;
        }

        case ARM64_INS_B:
        case ARM64_INS_BR:
            e = RDILFunction_GOTO(il, ARM64Lifter::liftOperand(h, arm64.operands[0], il));
            break;

        case ARM64_INS_BL:
        case ARM64_INS_BLR:
            e = RDILFunction_CALL(il, ARM64Lifter::liftOperand(h, arm64.operands[0], il));
            break;

        default:
            e = RDILFunction_UNKNOWN(il);
            break;
    }

    RDILFunction_Append(il, e);
}

RDILExpression* ARM64Lifter::liftOperand(csh h, const cs_arm64_op& op, RDILFunction* il)
{
    switch(op.type)
    {
        case ARM64_OP_REG: return RDILFunction_REG(il, sizeof(u64), cs_reg_name(h, op.reg));
        case ARM64_OP_IMM: return RDILFunction_CNST(il, sizeof(u64), static_cast<u64>(op.imm));
        case ARM64_OP_MEM: break;
        default: break;
    }

    return RDILFunction_UNKNOWN(il);
}

RDILExpression* ARM64Lifter::liftConditionalJump(csh h, const cs_insn* insn, RDILExpression* cond, RDILFunction* il)
{
    auto* t = RDILFunction_GOTO(il, ARM64Lifter::liftOperand(h, insn->detail->arm64.operands[1], il));
    auto* f = RDILFunction_GOTO(il, RDILFunction_CNST(il, sizeof(u64), insn->address + insn->size));
    return RDILFunction_IF(il, cond, t, f);
}

RDILExpression* ARM64Lifter::liftMath(csh h, unsigned int id, const cs_arm64& arm64, RDILFunction* il)
{
    if(arm64.op_count != 3) return RDILFunction_UNKNOWN(il);

    auto* dst = ARM64Lifter::liftOperand(h, arm64.operands[0], il);
    auto* src1 = ARM64Lifter::liftOperand(h, arm64.operands[1], il);
    auto* src2 = ARM64Lifter::liftOperand(h, arm64.operands[2], il);

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
