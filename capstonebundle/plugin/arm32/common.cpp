#include "common.h"
#include "../arm/common.h"

void ARM32Common::emulate(Capstone* capstone, RDEmulateResult* result, const cs_insn* insn)
{
    rd_address address = ARM_PC(RDEmulateResult_GetAddress(result));
    const auto& arm = insn->detail->arm;

    switch(insn->id)
    {
        case ARM_INS_B: {
            if(arm.cc != ARM_CC_AL) {
                RDEmulateResult_AddBranchTrue(result, arm.operands[0].imm);
                RDEmulateResult_AddBranchFalse(result, address + insn->size);
            }
            else
                RDEmulateResult_AddBranch(result, arm.operands[0].imm);

            return;
        }

        case ARM_INS_BLX: {
            if(arm.operands[0].type != ARM_OP_IMM) return;

            if(arm.cc != ARM_CC_AL) {

            }
            else {
                if(ARM_IS_THUMB(arm.operands[0].imm))
                    RDContext_SetAddressAssembler(capstone->context(), ARM_PC(arm.operands[0].imm), capstone->endianness() == Endianness_Big ? THUMBBE_ID : THUMBLE_ID);
                else
                    RDContext_SetAddressAssembler(capstone->context(), ARM_PC(arm.operands[0].imm), capstone->endianness() == Endianness_Big ? ARM32BE_ID : ARM32LE_ID);

                RDEmulateResult_AddCall(result, ARM_PC(arm.operands[0].imm));
            }

            break;
        }

        case ARM_INS_BL: RDEmulateResult_AddCall(result, arm.operands[0].imm); return;
        case ARM_INS_LDM: ARM32Common::checkFlowFrom(arm, result, 1); return;

        case ARM_INS_POP:
        case ARM_INS_LDR:
        case ARM_INS_MOV: ARM32Common::checkFlow(arm, result, 0); break;
        default: break;
    }

    ARM32Common::processOperands(arm, address, result);
}

void ARM32Common::render(Capstone* capstone, const RDRendererParams* rp, const cs_insn* insn)
{
    const auto& arm = insn->detail->arm;
    auto [startidx, endidx] = ARM32Common::checkWrap(insn);

    RDRenderer_MnemonicWord(rp->renderer, insn->mnemonic, ARM32Common::mnemonicTheme(insn));

    for(size_t i = 0; i < arm.op_count; i++)
    {
        if(i) RDRenderer_Text(rp->renderer, ", ");
        if(startidx == i) RDRenderer_Text(rp->renderer, "{");

        const auto& op = arm.operands[i];

        switch(op.type)
        {
            case ARM_OP_MEM: {
                if(ARM32Common::isMemPC(op.mem)) RDRenderer_Reference(rp->renderer, ARM32Common::pc(rp->address) + op.mem.disp); // [pc]
                else ARM32Common::renderMemory(capstone, arm, op, rp);
                break;
            }

            case ARM_OP_REG: RDRenderer_Register(rp->renderer, capstone->regName(op.reg)); break;
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

const char* ARM32Common::checkAssembler(Capstone* capstone, rd_address address)
{
    if(capstone->arch() == CS_ARCH_ARM)
    {
        //if(ARM_IS_THUMB(address) ||
           //(!std::string(RDContext_GetAddressAssembler(m_context, address)).find("thumb")) ||

        if(capstone->endianness() == Endianness_Big)
        {

        }
        else
        {

        }
    }

}

void ARM32Common::renderMemory(Capstone* capstone, const cs_arm& arm, const cs_arm_op& op, const RDRendererParams* rp)
{
    RDRenderer_Text(rp->renderer, "[");

    if(op.mem.base != ARM_REG_INVALID)
        RDRenderer_Register(rp->renderer, capstone->regName(op.mem.base));

    if(op.mem.index != ARM_REG_INVALID)
    {
        if(op.mem.base != ARM_REG_INVALID) RDRenderer_Text(rp->renderer, ", ");
        RDRenderer_Register(rp->renderer, capstone->regName(op.mem.index));
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

void ARM32Common::checkFlowFrom(const cs_arm& arm, RDEmulateResult* result, int startidx)
{
    for(int i = startidx; i < arm.op_count; i++)
    {
        const auto& op = arm.operands[i];
        if(op.type != ARM_OP_REG) continue;
        if(arm.operands[i].type != ARM_OP_REG) continue;
        if(arm.operands[i].reg != ARM_REG_PC) continue;
        RDEmulateResult_AddReturn(result);
    }
}

void ARM32Common::checkFlow(const cs_arm& arm, RDEmulateResult* result, int opidx)
{
    if(opidx >= arm.op_count) return;
    if(arm.operands[opidx].type != ARM_OP_REG) return;

    if(arm.operands[opidx].reg == ARM_REG_PC)
        RDEmulateResult_AddReturn(result);
}

void ARM32Common::processOperands(const cs_arm& arm, rd_address address, RDEmulateResult* result)
{
    for(auto i = 0; i < arm.op_count; i++)
    {
        const auto& op = arm.operands[i];

        switch(op.type)
        {
            case ARM_OP_IMM: RDEmulateResult_AddReference(result, op.imm); break;

            case ARM_OP_MEM: {
                if(ARM32Common::isMemPC(op.mem))
                    RDEmulateResult_AddReference(result, ARM32Common::pc(address) + op.mem.disp);

                break;
            }

            default: break;
        }
    }
}

bool ARM32Common::isMemPC(const arm_op_mem& mem) { return (mem.index == ARM_REG_INVALID) && (mem.base == ARM_REG_PC);  }

rd_address ARM32Common::pc(rd_address address)
{
    /*
     * https://stackoverflow.com/questions/24091566/why-does-the-arm-pc-register-point-to-the-instruction-after-the-next-one-to-be-e
     *
     * In ARM state:
     *  - The value of the PC is the address of the current instruction plus 8 bytes.
     */

    return address + 8;
}

std::pair<size_t, size_t> ARM32Common::checkWrap(const cs_insn* insn)
{
    switch(insn->id)
    {
        case ARM_INS_PUSH:
        case ARM_INS_POP: return {0, RD_NVAL};

        case ARM_INS_LDM: return {1, RD_NVAL};
        default: break;
    }

    return {RD_NVAL, RD_NVAL};
}

rd_type ARM32Common::mnemonicTheme(const cs_insn* insn)
{
    const auto& arm = insn->detail->arm;

    switch(insn->id)
    {
        case ARM_INS_B: return (arm.cc == ARM_CC_AL) ? Theme_Jump : Theme_JumpCond;
        case ARM_INS_BL: return Theme_Call;
        default: break;
    }

    return Theme_Default;
}
