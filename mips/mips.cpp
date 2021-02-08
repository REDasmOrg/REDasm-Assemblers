#include "mips.h"
#include "mips_registers.h"
#include "mips_decoder.h"

std::array<MIPS::Callback_MIPSDecode, MIPSEncoding_Count> MIPS::m_renderers = {
    [](const MIPSDecodedInstruction*, const RDRendererParams*) { },
    &MIPS::renderR, &MIPS::renderI, &MIPS::renderJ, &MIPS::renderB,
    &MIPS::renderC0, &MIPS::renderC1, &MIPS::renderC2,
};

void MIPS::initialize() { MIPSInitializeFormats(); }

void MIPS::emulate(const MIPSDecodedInstruction* decoded, RDEmulateResult* result)
{
    RDEmulateResult_SetSize(result, decoded->size);
    rd_address address = RDEmulateResult_GetAddress(result);

    switch(decoded->opcode->id)
    {
        case MIPSMacro_B:
        case MIPSInstruction_J: {
            auto baddress = MIPSDecoder::calcAddress(decoded, address);
            if(baddress) RDEmulateResult_AddBranch(result, *baddress);
            else RDEmulateResult_AddBranchUnresolved(result);
            RDEmulateResult_SetDelaySlot(result, 1);
            break;
        }

        case MIPSInstruction_Jal: {
            auto baddress = MIPSDecoder::calcAddress(decoded, address);
            if(baddress) RDEmulateResult_AddCall(result, *baddress);
            else RDEmulateResult_AddBranchUnresolved(result);
            RDEmulateResult_SetDelaySlot(result, 1);
            break;
        }

        case MIPSInstruction_Beq:
        case MIPSInstruction_Bne:
        case MIPSInstruction_Bgez:
        case MIPSInstruction_Bgtz:
        case MIPSInstruction_Blez: {
            auto baddress = MIPSDecoder::calcAddress(decoded, address);
            if(baddress) RDEmulateResult_AddBranchTrue(result, *baddress);
            else RDEmulateResult_AddBranchUnresolved(result);
            RDEmulateResult_AddBranchFalse(result, address + (sizeof(MIPSInstruction) * 2));
            RDEmulateResult_SetDelaySlot(result, 1);
            break;
        }

        case MIPSInstruction_Jalr:
        case MIPSInstruction_Jr:
            RDEmulateResult_AddReturn(result);
            RDEmulateResult_SetDelaySlot(result, 1);
            break;

        case MIPSMacro_La:
            RDEmulateResult_AddReference(result, decoded->macro.regimm.address);
            break;

        case MIPSMacro_Lw:
        case MIPSMacro_Sw:
            RDEmulateResult_AddReferenceSize(result, decoded->macro.regimm.address, sizeof(u32));
            break;

        case MIPSMacro_Lhu:
        case MIPSMacro_Sh:
            RDEmulateResult_AddReferenceSize(result, decoded->macro.regimm.address, sizeof(u16));
            break;

        case MIPSInstruction_Break: RDEmulateResult_AddReturn(result); break;
        default: break;
    }
}

void MIPS::renderInstruction(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    MIPS::renderMnemonic(decoded, rp);

    switch(decoded->opcode->id)
    {
        case MIPSInstruction_Lb:
        case MIPSInstruction_Lbu:
        case MIPSInstruction_Lw:
        case MIPSInstruction_Lwl:
        case MIPSInstruction_Lwr:
        case MIPSInstruction_Sb:
        case MIPSInstruction_Sh:
        case MIPSInstruction_Sw: MIPS::renderLoadStore(decoded, rp); return;
        default: break;
    }

    if(decoded->opcode->category == MIPSCategory_Macro)
    {
        MIPS::renderMacro(decoded, rp);
        return;
    }

    if(decoded->opcode->encoding >= m_renderers.size()) return;
    auto r = m_renderers[decoded->opcode->encoding];
    r(decoded, rp);
}

void MIPS::renderMnemonic(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    switch(decoded->opcode->id)
    {
        case MIPSMacro_Nop: RDRenderer_MnemonicWord(rp->renderer, decoded->opcode->mnemonic, Theme_Nop); return;
        case MIPSMacro_B: RDRenderer_MnemonicWord(rp->renderer, decoded->opcode->mnemonic, Theme_Jump); return;
        default: break;
    }

    rd_type theme = Theme_Default;

    switch(decoded->opcode->category)
    {
        case MIPSCategory_Jump: theme = Theme_Jump; break;
        case MIPSCategory_JumpCond: theme = Theme_JumpCond; break;
        case MIPSCategory_Call: theme = Theme_Call; break;
        case MIPSCategory_Ret: theme = Theme_Ret; break;
        default: break;
    }

    RDRenderer_MnemonicWord(rp->renderer, decoded->opcode->mnemonic, theme);
}

void MIPS::renderR(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    switch(decoded->opcode->id)
    {
        case MIPSInstruction_Sll:
        case MIPSInstruction_Srl:
        case MIPSInstruction_Sra:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rd));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rt));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Unsigned(rp->renderer, decoded->instruction.r.shamt);
            break;

        case MIPSInstruction_Jalr:
            if(decoded->instruction.r.rd != MIPSRegister_RA) {
                RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rd));
                RDRenderer_Text(rp->renderer, ", ");
                RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rs));
            } else
                RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rs));
            break;

        case MIPSInstruction_Jr:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rs));
            break;

        default:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rd));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rs));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rt));
            break;
    }
}

void MIPS::renderI(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    if(decoded->opcode->id == MIPSInstruction_Lui)
    {
        RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rt));
        RDRenderer_Text(rp->renderer, ", ");
        RDRenderer_Unsigned(rp->renderer, decoded->instruction.i_u.immediate);
        return;
    }

    if((decoded->opcode->category == MIPSCategory_Jump) || (decoded->opcode->category == MIPSCategory_JumpCond))
    {
        auto addr = MIPSDecoder::calcAddress(decoded, rp->address);
        if(addr) RDRenderer_Reference(rp->renderer, *addr);
        else RDRenderer_Unknown(rp->renderer);
    }
    else
    {
        RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rt));
        RDRenderer_Text(rp->renderer, ", ");
        RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rs));
        RDRenderer_Text(rp->renderer, ", ");
        RDRenderer_Unsigned(rp->renderer, decoded->instruction.i_u.immediate);
    }
}

void MIPS::renderJ(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    auto addr = MIPSDecoder::calcAddress(decoded, rp->address);

    if(addr) RDRenderer_Reference(rp->renderer, *addr);
    else RDRenderer_Unknown(rp->renderer);
}

void MIPS::renderB(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp) { RDRenderer_Unsigned(rp->renderer, decoded->instruction.b.code); }

void MIPS::renderC0(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    switch(decoded->opcode->id)
    {
        case MIPSInstruction_Mfc0:
        case MIPSInstruction_Mtc0:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.c0sel.rt));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Register(rp->renderer, MIPSDecoder::cop0reg(decoded->instruction.c0sel.rd));

            if(decoded->instruction.c0sel.sel) {
                RDRenderer_Text(rp->renderer, ", ");
                RDRenderer_Unsigned(rp->renderer, decoded->instruction.c0sel.sel);
            }

            break;

        default:
            break;
    }
}

void MIPS::renderC1(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{

}

void MIPS::renderC2(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    switch(decoded->opcode->id)
    {
        case MIPSInstruction_Ctc2:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.c2impl.rt));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Register(rp->renderer, ("$" + std::to_string(decoded->instruction.c2impl.rd)).c_str());
            break;

        default:
            break;
    }
}

void MIPS::renderMacro(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    switch(decoded->opcode->id)
    {
        case MIPSMacro_Move:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rd));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.r.rs));
            break;

        case MIPSMacro_B:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rt));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rs));
            break;

        case MIPSMacro_Li:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rt));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Unsigned(rp->renderer, decoded->instruction.i_u.immediate);
            break;

        case MIPSMacro_La:
        case MIPSMacro_Lw:
        case MIPSMacro_Lhu:
        case MIPSMacro_Sw:
        case MIPSMacro_Sh:
            RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->macro.regimm.reg));
            RDRenderer_Text(rp->renderer, ", ");
            RDRenderer_Reference(rp->renderer, decoded->macro.regimm.address);
            break;

        case MIPSMacro_Nop: break;
        default: rd_log("Unhandled instruction: '" + std::string(decoded->opcode->mnemonic) + "'"); break;
    }
}

void MIPS::renderLoadStore(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp)
{
    RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rt));
    RDRenderer_Text(rp->renderer, ", ");
    RDRenderer_Unsigned(rp->renderer, decoded->instruction.i_u.immediate);
    RDRenderer_Text(rp->renderer, "(");
    RDRenderer_Register(rp->renderer, MIPSDecoder::reg(decoded->instruction.i_u.rs));
    RDRenderer_Text(rp->renderer, ")");
}
