#include "arm.h"
#include <unordered_set>

ARM::ARM(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_ARM, mode) { }

void ARM::emulate(RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);
    if(!this->decode(address, RDEmulateResult_GetView(result))) return;

    auto& arm = this->arm();
    RDEmulateResult_SetSize(result, m_insn->size);

    switch(m_insn->id)
    {
        case ARM_INS_B: {
            if(arm.cc != ARM_CC_AL) {
                RDEmulateResult_AddBranchTrue(result, arm.operands[0].imm);
                RDEmulateResult_AddBranchFalse(result, address + m_insn->size);
            }
            else
                RDEmulateResult_AddBranch(result, arm.operands[0].imm);

            return;
        }

        case ARM_INS_BL: RDEmulateResult_AddCall(result, arm.operands[0].imm); return;
        case ARM_INS_LDM: this->checkFlowFrom(result, 1); return;

        case ARM_INS_POP:
        case ARM_INS_LDR:
        case ARM_INS_MOV: this->checkFlow(result, 0); break;
        default: break;
    }

    this->processOperands(address, result);
}

void ARM::render(const RDRendererParams* rp)
{
    if(!this->decode(rp->address, &rp->view)) return;

    RDRenderer_MnemonicWord(rp->renderer, m_insn->mnemonic, this->mnemonicTheme());
    auto& arm = this->arm();

    auto [startidx, endidx] = this->checkWrap();

    for(size_t i = 0; i < arm.op_count; i++)
    {
        if(i) RDRenderer_Text(rp->renderer, ", ");
        if(startidx == i) RDRenderer_Text(rp->renderer, "{");

        const auto& op = arm.operands[i];

        switch(op.type)
        {
            case ARM_OP_MEM: {
                if(this->isMemPC(op.mem)) RDRenderer_Reference(rp->renderer, this->pc(rp->address) + op.mem.disp); // [pc]
                else this->renderMemory(arm, op, rp);
                break;
            }

            case ARM_OP_REG: RDRenderer_Register(rp->renderer, this->regName(op.reg)); break;
            case ARM_OP_IMM: RDRenderer_Reference(rp->renderer, op.imm); break;

            case ARM_OP_FP: RDRenderer_Text(rp->renderer, "ARM_OP_FP"); break;
            case ARM_OP_CIMM: RDRenderer_Text(rp->renderer, "ARM_OP_CIMM"); break;
            case ARM_OP_PIMM: RDRenderer_Text(rp->renderer, "ARM_OP_PIMM"); break;
            case ARM_OP_SETEND: RDRenderer_Text(rp->renderer, "ARM_OP_SETEND"); break;
            case ARM_OP_SYSREG: RDRenderer_Text(rp->renderer, "ARM_OP_SYSREG"); break;
            default: break;
        }

        if((endidx - 1) == i) RDRenderer_Text(rp->renderer, "}");
    }

    if((startidx != RD_NVAL) && (endidx == RD_NVAL))
        RDRenderer_Text(rp->renderer, "}");
}

rd_address ARM::pc(rd_address address) const
{
    /*
     * https://stackoverflow.com/questions/24091566/why-does-the-arm-pc-register-point-to-the-instruction-after-the-next-one-to-be-e
     *
     * In ARM state:
     *  - The value of the PC is the address of the current instruction plus 8 bytes.
     */

    return address + 8;
}

std::pair<size_t, size_t> ARM::checkWrap() const
{
    switch(m_insn->id)
    {
        case ARM_INS_PUSH:
        case ARM_INS_POP: return {0, RD_NVAL};

        case ARM_INS_LDM: return {1, RD_NVAL};
        default: break;
    }

    return {RD_NVAL, RD_NVAL};
}

bool ARM::isMemPC(const arm_op_mem& mem) const { return (mem.index == ARM_REG_INVALID) && (mem.base == ARM_REG_PC); }

void ARM::checkFlowFrom(RDEmulateResult* result, int startidx) const
{
    auto& arm = this->arm();

    for(int i = startidx; i < arm.op_count; i++)
    {
        const auto& op = arm.operands[i];
        if(op.type != ARM_OP_REG) continue;
        if(arm.operands[i].type != ARM_OP_REG) continue;
        if(arm.operands[i].reg != ARM_REG_PC) continue;
        RDEmulateResult_AddReturn(result);
    }
}

const cs_arm& ARM::arm() const { return m_insn->detail->arm; }

rd_type ARM::mnemonicTheme() const
{
    auto& arm = this->arm();

    switch(m_insn->id)
    {
        case ARM_INS_B: return (arm.cc == ARM_CC_AL) ? Theme_Jump : Theme_JumpCond;
        case ARM_INS_BL: return Theme_Call;
        default: break;
    }

    return Theme_Default;
}

void ARM::checkFlow(RDEmulateResult* result, int opidx) const
{
    auto& arm = this->arm();
    if(opidx >= arm.op_count) return;
    if(arm.operands[opidx].type != ARM_OP_REG) return;

    if(arm.operands[opidx].reg == ARM_REG_PC)
        RDEmulateResult_AddReturn(result);
}

void ARM::processOperands(rd_address address, RDEmulateResult* result) const
{
    auto& arm = this->arm();

    for(auto i = 0; i < arm.op_count; i++)
    {
        const auto& op = arm.operands[i];

        switch(op.type)
        {
            case ARM_OP_IMM: RDEmulateResult_AddReference(result, op.imm); break;

            case ARM_OP_MEM: {
                if(this->isMemPC(op.mem))
                    RDEmulateResult_AddReference(result, this->pc(address) + op.mem.disp);

                break;
            }

            default: break;
        }
    }
}

void ARM::renderMemory(const cs_arm& arm, const cs_arm_op& op, const RDRendererParams* rp) const
{
    RDRenderer_Text(rp->renderer, "[");

    if(op.mem.base != ARM_REG_INVALID)
        RDRenderer_Register(rp->renderer, this->regName(op.mem.base));

    if(op.mem.index != ARM_REG_INVALID)
    {
        if(op.mem.base != ARM_REG_INVALID) RDRenderer_Text(rp->renderer, ", ");
        RDRenderer_Register(rp->renderer, this->regName(op.mem.index));
    }

    if(op.mem.disp)
    {
        if(op.mem.base != ARM_REG_INVALID) RDRenderer_Text(rp->renderer, ", ");
        RDRenderer_Text(rp->renderer, "#");
        RDRenderer_Signed(rp->renderer, op.mem.disp);
    }

    RDRenderer_Text(rp->renderer, "]");
    if(arm.writeback) RDRenderer_Text(rp->renderer, "!");
}

ARMLE::ARMLE(RDContext* ctx): ARM(ctx, CS_MODE_LITTLE_ENDIAN) { }
ARMBE::ARMBE(RDContext* ctx): ARM(ctx, CS_MODE_BIG_ENDIAN) { }
