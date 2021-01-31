#include "arm64.h"
#include "arm64_lifter.h"

ARM64::ARM64(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_ARM64, mode) { m_lifter.reset(new ARM64Lifter(ctx)); }

void ARM64::renderMemory(const cs_arm64& arm64, const cs_arm64_op& op, const RDRendererParams* rp) const
{
    RDRenderer_Text(rp->renderer, "[");

    if(op.mem.base != ARM64_REG_INVALID)
        this->renderRegister(rp, op.mem.base);

    if(op.mem.index != ARM64_REG_INVALID)
    {
        if(op.mem.base != ARM64_REG_INVALID) RDRenderer_Text(rp->renderer, ", ");
        this->renderRegister(rp, op.mem.index);
    }

    if(op.mem.disp)
    {
        if((op.mem.base != ARM64_REG_INVALID) || (op.mem.index != ARM64_REG_INVALID))
            RDRenderer_Text(rp->renderer, ", ");

        RDRenderer_Text(rp->renderer, "#");
        RDRenderer_Signed(rp->renderer, op.mem.disp);
    }

    RDRenderer_Text(rp->renderer, "]");
    if(arm64.writeback) RDRenderer_Text(rp->renderer, "!");
}

void ARM64::renderMnemonic(const RDRendererParams* rp)
{
    rd_type theme = Theme_Default;

    if(cs_insn_group(m_handle, m_insn, CS_GRP_JUMP))
    {
        if(m_insn->detail->arm64.cc == ARM64_CC_INVALID) theme = Theme_Jump;
        else theme = Theme_JumpCond;
    }
    else if(cs_insn_group(m_handle, m_insn, CS_GRP_CALL)) theme = Theme_Call;
    else if(cs_insn_group(m_handle, m_insn, CS_GRP_RET)) theme = Theme_Ret;

    RDRenderer_Mnemonic(rp->renderer, m_insn->mnemonic, theme);
    RDRenderer_Text(rp->renderer, " ");
}

void ARM64::render(const RDRendererParams* rp)
{
    if(!this->decode(rp->address, &rp->view)) return;
    this->renderMnemonic(rp);

    const auto& arm64 = m_insn->detail->arm64;

    for(auto i = 0; i < arm64.op_count; i++)
    {
        if(i) RDRenderer_Text(rp->renderer, ", ");

        const auto& op = arm64.operands[i];

        switch(op.type)
        {
            case ARM64_OP_REG: this->renderRegister(rp, op.reg); break;
            case ARM64_OP_IMM: RDRenderer_Reference(rp->renderer, op.imm); break;
            case ARM64_OP_MEM: this->renderMemory(arm64, op, rp); break;

            case ARM64_OP_FP:
            case ARM64_OP_CIMM:
            case ARM64_OP_REG_MRS:
            case ARM64_OP_REG_MSR:
            case ARM64_OP_PSTATE:
            case ARM64_OP_SYS:
            case ARM64_OP_PREFETCH:
            case ARM64_OP_BARRIER:
            default:
                RDRenderer_Text(rp->renderer, ("(? " + std::to_string(op.type) + " ?)").c_str());
                break;
        }
    }
}

void ARM64::emulate(RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);
    if(!this->decode(address, RDEmulateResult_GetView(result))) return;
    RDEmulateResult_SetSize(result, m_insn->size);

    const auto& arm64 = m_insn->detail->arm64;

    if(cs_insn_group(m_handle, m_insn, CS_GRP_JUMP))
    {
        switch(m_insn->id)
        {
            case ARM64_INS_BL: {
                if(arm64.operands[0].type == ARM64_OP_IMM)
                    RDEmulateResult_AddCall(result, static_cast<rd_address>(arm64.operands[0].imm));
                else
                    rd_log("Unhandled BL branch @ " + rd_tohex(address));
                break;
            }

            case ARM64_INS_CBZ:
            case ARM64_INS_CBNZ:
                RDEmulateResult_AddBranchTrue(result, static_cast<rd_address>(arm64.operands[1].imm));
                RDEmulateResult_AddBranchFalse(result, address + m_insn->size);
                break;

            case ARM64_INS_TBZ:
            case ARM64_INS_TBNZ:
                RDEmulateResult_AddBranchTrue(result, static_cast<rd_address>(arm64.operands[2].imm));
                RDEmulateResult_AddBranchFalse(result, address + m_insn->size);
                break;

            case ARM64_INS_B: RDEmulateResult_AddBranch(result, static_cast<rd_address>(arm64.operands[0].imm)); break;
            case ARM64_INS_BR: RDEmulateResult_AddBranchUnresolved(result); break;
            case ARM64_INS_BLR: RDEmulateResult_AddCallUnresolved(result); break;
            default: rdcontext_addproblem(m_context, this->instructionText()); break;
        }

        return;
    }

    if(cs_insn_group(m_handle, m_insn, CS_GRP_RET))
    {
        RDEmulateResult_AddReturn(result);
        return;
    }

    for(size_t i = 0; i < arm64.op_count; i++)
    {
        const auto& op = arm64.operands[i];
        if(op.type != ARM64_OP_IMM) continue;
        RDEmulateResult_AddReference(result, op.imm);
    }
}

ARM64LE::ARM64LE(RDContext* ctx): ARM64(ctx, CS_MODE_LITTLE_ENDIAN) { }
ARM64BE::ARM64BE(RDContext* ctx): ARM64(ctx, CS_MODE_BIG_ENDIAN) { }
