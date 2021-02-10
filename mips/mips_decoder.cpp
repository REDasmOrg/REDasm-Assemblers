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

const char* MIPSDecoder::copNreg(u32 r)
{
    static std::string copreg;
    copreg = "$" + std::to_string(r);
    return copreg.c_str();
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

        case MIPSEncoding_C: {
            auto& format = MIPSOpcodes_C[decoded->instruction.c.funct];
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

        case MIPSEncoding_CLS: {
            auto& format = MIPSOpcodes_CLS[decoded->instruction.cls.op];
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
        switch(mi->b.funct)
        {
            case 0b001100:
            case 0b001101: return MIPSEncoding_B;

            case 0b110000:
            case 0b110100: return MIPSEncoding_C;
            default: break;
        }

        return MIPSEncoding_R;
    }

    switch(mi->unk.op)
    {
        case 0b010000: return MIPSEncoding_C0;
        //case 0b010001: return MIPSEncoding_C1;
        case 0b010010: return MIPSEncoding_C2;

        case 0b110001:
        case 0b111001:
        case 0b110010:
        case 0b111010: return MIPSEncoding_CLS;

        default: break;
    }

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
            default: rd_log("Cannot calculate address of '" + std::string(decoded->opcode->mnemonic) + "'"); break;
        }
    }

    return std::nullopt;
}
