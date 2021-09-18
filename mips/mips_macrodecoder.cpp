#include "mips_macrodecoder.h"
#include "mips_registers.h"
#include "mips_decoder.h"
#include "mips_format.h"
#include <unordered_map>

void MIPSMacroDecoder::checkMacro(MIPSDecodedInstruction* decoded, const RDBufferView* view, Swap32_Callback swapcb)
{
    switch(decoded->opcode->id)
    {
        case MIPSInstruction_Ori:
        case MIPSInstruction_Addi:
        case MIPSInstruction_Addiu: MIPSMacroDecoder::checkLi(decoded); break;

        case MIPSInstruction_Addu: MIPSMacroDecoder::checkMove(decoded); break;
        case MIPSInstruction_Lui: MIPSMacroDecoder::checkLui(decoded, *view, swapcb); break;
        case MIPSInstruction_Sll: MIPSMacroDecoder::checkNop(decoded); break;
        case MIPSInstruction_Beq: MIPSMacroDecoder::checkB(decoded); break;
        default: break;
    }
}

void MIPSMacroDecoder::applyMacro(const std::string& mnemonic, MIPSDecodedInstruction* decoded)
{
    const auto& [macro, size] = MIPSOpcodes_Macro.at(mnemonic);
    decoded->opcode = &macro;
    decoded->size = size;
}

void MIPSMacroDecoder::checkLui(MIPSDecodedInstruction* luidecoded, RDBufferView view, Swap32_Callback swapcb)
{
    static const std::unordered_map<rd_type, const char*> LUI_MACROS = {
        { MIPSInstruction_Addiu, "la" }, { MIPSInstruction_Ori, "la" },
        { MIPSInstruction_Lhu, "lhu" }, { MIPSInstruction_Lw, "lw" },
        { MIPSInstruction_Sw, "sw" }, { MIPSInstruction_Sh, "sh" },
    };

    MIPSDecodedInstruction nextdecoded;
    RDBufferView_Move(&view, sizeof(MIPSInstruction));
    if(!MIPSDecoder::decodeOne(&view, &nextdecoded, swapcb)) return;
    if(!MIPSMacroDecoder::canSimplifyLui(luidecoded, &nextdecoded)) return;

    u32 mipsaddress = luidecoded->instruction.i_u.immediate << 16;

    switch(nextdecoded.opcode->id)
    {
        case MIPSInstruction_Ori:
            mipsaddress |= static_cast<u32>(nextdecoded.instruction.i_u.immediate);
            break;

        case MIPSInstruction_Addiu:
        case MIPSInstruction_Lw:
        case MIPSInstruction_Lhu:
        case MIPSInstruction_Sw:
        case MIPSInstruction_Sh:
            mipsaddress += static_cast<u32>(RD_SignExt(nextdecoded.instruction.i_u.immediate, 16));
            break;

        default: return;
    }

    luidecoded->macro.regimm.reg = nextdecoded.instruction.i_u.rt;
    luidecoded->macro.regimm.address = mipsaddress;
    MIPSMacroDecoder::applyMacro(LUI_MACROS.at(nextdecoded.opcode->id), luidecoded);
}

void MIPSMacroDecoder::checkLi(MIPSDecodedInstruction* decoded)
{
    if(decoded->instruction.i_u.rs != MIPSRegister_ZERO) return;
    MIPSMacroDecoder::applyMacro("li", decoded);
}

void MIPSMacroDecoder::checkMove(MIPSDecodedInstruction* decoded)
{
    if(decoded->instruction.r.rt != MIPSRegister_ZERO) return;
    MIPSMacroDecoder::applyMacro("move", decoded);
}

void MIPSMacroDecoder::checkNop(MIPSDecodedInstruction* decoded)
{
    if(decoded->instruction.r.rd != MIPSRegister_ZERO) return;
    if(decoded->instruction.r.rt != MIPSRegister_ZERO) return;
    MIPSMacroDecoder::applyMacro("nop", decoded);
}

void MIPSMacroDecoder::checkB(MIPSDecodedInstruction* decoded)
{
    if(decoded->instruction.i_u.rt != decoded->instruction.i_u.rs) return;
    MIPSMacroDecoder::applyMacro("b", decoded);
}

bool MIPSMacroDecoder::canSimplifyLui(const MIPSDecodedInstruction* luidecoded, const MIPSDecodedInstruction* decoded)
{
    switch(decoded->opcode->encoding)
    {
        case MIPSEncoding_I: return luidecoded->instruction.i_u.rt == decoded->instruction.i_u.rs;

        case MIPSEncoding_R: {
            if(decoded->instruction.r.rd != decoded->instruction.r.rs) return false;
            return (luidecoded->instruction.i_u.rt == MIPSRegister_AT) && (decoded->instruction.r.rd == MIPSRegister_AT);
        }

        default: break;
    }

    return false;
}
