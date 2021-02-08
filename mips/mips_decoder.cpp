#include "mips_decoder.h"
#include "mips_registers.h"
#include "mips_macrodecoder.h"
#include <climits>

const char* MIPSDecoder::reg(u32 r)
{
    if(r > GPR_REGISTERS.size()) return nullptr;
    return GPR_REGISTERS[r];
}

bool MIPSDecoder::decode(const RDBufferView* view, MIPSDecodedInstruction* decoded, Swap32_Callback swapcb)
{
    if(!MIPSDecoder::decodeOne(view, decoded, swapcb)) return false;
    MIPSMacroDecoder::checkMacro(decoded, view, swapcb);
    return true;
}

const char* MIPSDecoder::cop0reg(u32 r)
{
    if(r > COP0_REGISTERS.size()) return nullptr;
    return COP0_REGISTERS[r];
}

bool MIPSDecoder::checkEncoding(MIPSDecodedInstruction* decoded)
{
    size_t f = MIPSDecoder::checkFormat(&decoded->instruction);

    switch(f)
    {
        case MIPSEncoding_R: {
            auto& format = MIPSOpcodes_R[decoded->instruction.r.funct];
            if(!format.mnemonic) return false;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_I: {
            auto& format = MIPSOpcodes_I[decoded->instruction.i_u.op];
            if(!format.mnemonic) return false;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_J: {
            auto& format = MIPSOpcodes_J[decoded->instruction.j.op];
            if(!format.mnemonic) return false;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_B: {
            auto& format = MIPSOpcodes_B[decoded->instruction.b.funct];
            if(!format.mnemonic) return false;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_C0: {
            auto& format = MIPSOpcodes_C0[decoded->instruction.c0sel.code];
            if(!format.mnemonic) return false;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_C2: {
            auto& format = MIPSOpcodes_C2[decoded->instruction.c2impl.code];
            if(!format.mnemonic) return false;
            decoded->opcode = &format;
            break;
        }

        default:
            decoded->instruction = { };
            decoded->opcode = nullptr;
            return false;
    }

    return f != MIPSEncoding_None;
}

size_t MIPSDecoder::checkFormat(const MIPSInstruction* mi)
{
    if(!mi->r.op)
    {
        if((mi->b.funct == 0b001100) || (mi->b.funct == 0b001101))
            return MIPSEncoding_B;

        return MIPSEncoding_R;
    }

    if(mi->unk.op == 0b010000) return MIPSEncoding_C0;
    //if(mi->unk.op == 0b010001) return MIPSEncoding_C1;
    if(mi->unk.op == 0b010010) return MIPSEncoding_C2;
    if(((mi->i_u.op >= 0x04) && (mi->i_u.op <= 0x2e)) || (mi->i_u.op == 0x01)) return MIPSEncoding_I;
    if((mi->j.op == 0x02) || (mi->j.op == 0x03)) return MIPSEncoding_J;
    return MIPSEncoding_None;
}

bool MIPSDecoder::decodeOne(const RDBufferView* view, MIPSDecodedInstruction* decoded, Swap32_Callback swapcb)
{
    decoded->instruction.word = swapcb(*reinterpret_cast<const u32*>(view->data));
    return MIPSDecoder::checkEncoding(decoded);
}

std::optional<rd_address> MIPSDecoder::calcAddress(const MIPSDecodedInstruction* decoded, rd_address address)
{
    if(decoded->opcode->category == MIPSCategory_Macro)
    {
        switch(decoded->opcode->id)
        {
            case MIPSMacro_B: return address + sizeof(MIPSInstruction) + static_cast<s32>(RD_SignExt(decoded->instruction.i_s.immediate << 2, 32));
            default: rd_log("Cannot calculate address of '" + std::string(decoded->opcode->mnemonic) + "'"); break;
        }
    }
    else
    {
        switch(decoded->opcode->encoding)
        {
            case MIPSEncoding_J: return (address & (0xF << ((sizeof(u32) * CHAR_BIT) - 4))) | (static_cast<u32>(decoded->instruction.j.target) << 2);
            case MIPSEncoding_I: return address + sizeof(MIPSInstruction) + static_cast<s32>(RD_SignExt(decoded->instruction.i_s.immediate << 2, 32));
            default: break;
        }
    }

    return std::nullopt;
}
