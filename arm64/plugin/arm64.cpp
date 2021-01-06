#include "arm64.h"

cs_insn* ARM64::m_insn = nullptr;

void ARM64::free(RDContext* ctx)
{
    csh h = static_cast<csh>(RDContext_GetUserData(ctx, ARM64_USERDATA));
    if(!h) return;

    cs_free(ARM64::m_insn, 1);
    cs_close(&h);
}

std::string ARM64::instructionText() { return std::string(m_insn->mnemonic) + " " + std::string(m_insn->op_str); }

bool ARM64::decode(csh h, rd_address address, const RDBufferView* view)
{
    const auto* pdata = reinterpret_cast<const uint8_t*>(view->data);
    size_t size = view->size;
    return cs_disasm_iter(h, &pdata, &size, &address, m_insn);
}

void ARM64::renderMemory(csh h, const cs_arm64& arm64, const cs_arm64_op& op, const RDRendererParams* rp)
{
    //rd_log("MEM @ " + rd_tohex(rp->address) + ", " + m_insn->op_str);
    RDRenderer_Text(rp->renderer, "[");

    if(op.mem.base != ARM64_REG_INVALID)
        RDRenderer_Register(rp->renderer, cs_reg_name(h, op.mem.base));

    if(op.mem.disp)
    {
        if(op.mem.base != ARM64_REG_INVALID) RDRenderer_Text(rp->renderer, ", ");

        RDRenderer_Text(rp->renderer, "#");
        RDRenderer_Signed(rp->renderer, op.mem.disp);
    }

    RDRenderer_Text(rp->renderer, "]");
    if(arm64.writeback) RDRenderer_Text(rp->renderer, "!");
}

void ARM64::renderMnemonic(csh h, const RDRendererParams* rp)
{
    rd_type theme = Theme_Default;

    if(cs_insn_group(h, m_insn, CS_GRP_JUMP))
    {
        if(m_insn->detail->arm64.cc == ARM64_CC_INVALID) theme = Theme_Jump;
        else theme = Theme_JumpCond;
    }
    else if(cs_insn_group(h, m_insn, CS_GRP_CALL)) theme = Theme_Call;
    else if(cs_insn_group(h, m_insn, CS_GRP_RET)) theme = Theme_Ret;

    RDRenderer_Mnemonic(rp->renderer, m_insn->mnemonic, theme);
    RDRenderer_Text(rp->renderer, " ");
}

void ARM64::render(csh h, const RDRendererParams* rp)
{
    if(!ARM64::decode(h, rp->address, &rp->view)) return;
    ARM64::renderMnemonic(h, rp);

    const auto& arm64 = m_insn->detail->arm64;

    for(auto i = 0; i < arm64.op_count; i++)
    {
        if(i) RDRenderer_Text(rp->renderer, ", ");

        const auto& op = arm64.operands[i];

        switch(op.type)
        {
            case ARM64_OP_REG: RDRenderer_Register(rp->renderer, cs_reg_name(h, op.reg)); break;
            case ARM64_OP_IMM: RDRenderer_Unsigned(rp->renderer, op.imm); break;
            case ARM64_OP_MEM: ARM64::renderMemory(h, arm64, op, rp); break;

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

void ARM64::emulate(csh h, RDContext* ctx, RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);
    if(!ARM64::decode(h, address, RDEmulateResult_GetView(result))) return;
    RDEmulateResult_SetSize(result, m_insn->size);

    const auto& arm64 = m_insn->detail->arm64;

    if(cs_insn_group(h, m_insn, CS_GRP_JUMP))
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
            default: rdcontext_addproblem(ctx, ARM64::instructionText()); break;
        }

        return;
    }

    if(cs_insn_group(h, m_insn, CS_GRP_RET))
    {
        RDEmulateResult_AddReturn(result);
        return;
    }

    if(address == 0xe06480)
    {
        int zzz = 0;
        zzz++;
    }

    for(size_t i = 0; i < arm64.op_count; i++)
    {
        const auto& op = arm64.operands[i];
        if(op.type != ARM64_OP_IMM) continue;
        RDEmulateResult_AddReference(result, op.imm);
    }
}
