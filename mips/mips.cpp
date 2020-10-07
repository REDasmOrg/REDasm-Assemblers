#include "mips.h"
#include "mips_registers.h"
#include <algorithm>
#include <sstream>
#include <climits>

//std::forward_list<RDInstruction> MIPSDecoder::m_luilist;

std::array<MIPSDecoder::Callback_MIPSDecode, MIPSEncoding_Count> MIPSDecoder::m_renderers = {
    [](const MIPSDecodedInstruction*, const RDRenderItemParams*) { },
    &MIPSDecoder::renderR,
    &MIPSDecoder::renderI,
    &MIPSDecoder::renderJ,
    &MIPSDecoder::renderB,
    &MIPSDecoder::renderC,
};

const char* MIPSDecoder::reg(u32 r)
{
    if(r > GPR_REGISTERS.size()) return nullptr;
    return GPR_REGISTERS[r];
}

template<MIPSDecoder::Swap_Callback Swap>
size_t MIPSDecoder::decode(const RDBufferView* view, MIPSDecodedInstruction* decoded)
{
    if(view->size < sizeof(u32)) return MIPSEncoding_Unknown;

    decoded->instruction.word = Swap(*reinterpret_cast<const u32*>(view->data));
    size_t f = MIPSDecoder::checkFormat(&decoded->instruction);

    switch(f)
    {
        case MIPSEncoding_R:
        {
            auto& format = MIPSOpcodes_R[decoded->instruction.r.funct];
            if(!format.mnemonic) return MIPSEncoding_Unknown;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_I:
        {
            auto& format = MIPSOpcodes_I[decoded->instruction.i.op];
            if(!format.mnemonic) return MIPSEncoding_Unknown;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_J:
        {
            auto& format = MIPSOpcodes_J[decoded->instruction.j.op];
            if(!format.mnemonic) return MIPSEncoding_Unknown;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_B:
        {
            auto& format = MIPSOpcodes_B[decoded->instruction.b.op];
            if(!format.mnemonic) return MIPSEncoding_Unknown;
            decoded->opcode = &format;
            break;
        }

        case MIPSEncoding_C:
        {
            auto& format = MIPSOpcodes_C[decoded->instruction.c.op];
            if(!format.mnemonic) return MIPSEncoding_Unknown;
            decoded->opcode = &format;
            break;
        }

        default:
            decoded->instruction = { };
            decoded->opcode = nullptr;
            break;
    }

    return f;
}

template<MIPSDecoder::Swap_Callback Swap>
void MIPSDecoder::emulate(RDContext*, RDEmulateResult* result)
{
    MIPSDecodedInstruction decoded;
    const RDBufferView* view = RDEmulateResult_GetView(result);
    size_t e = MIPSDecoder::decode<Swap>(view, &decoded);
    if(e == MIPSEncoding_Unknown) return;

    RDEmulateResult_SetSize(result, sizeof(MIPSInstruction));
    rd_address address = RDEmulateResult_GetAddress(result);

    switch(decoded.opcode->id)
    {
        case MIPSInstruction_J:
        {
            auto baddress = MIPSDecoder::calcAddress(&decoded, address);
            if(baddress) RDEmulateResult_AddBranch(result, *baddress);
            RDEmulateResult_SetDelaySlot(result, 1);
            break;
        }

        case MIPSInstruction_Jal:
        {
            auto baddress = MIPSDecoder::calcAddress(&decoded, address);
            if(baddress) RDEmulateResult_AddCall(result, *baddress);
            RDEmulateResult_SetDelaySlot(result, 1);
            break;
        }

        case MIPSInstruction_Beq:
        case MIPSInstruction_Bne:
        case MIPSInstruction_Bgez:
        case MIPSInstruction_Bgtz:
        case MIPSInstruction_Blez:
        {
            auto baddress = MIPSDecoder::calcAddress(&decoded, address);
            if(baddress) RDEmulateResult_AddBranchTrue(result, *baddress);
            RDEmulateResult_AddBranchFalse(result, address + (sizeof(MIPSInstruction) * 2));
            RDEmulateResult_SetDelaySlot(result, 1);
            break;
        }

        case MIPSInstruction_Jalr:
        case MIPSInstruction_Jr:
            RDEmulateResult_AddReturn(result);
            RDEmulateResult_SetDelaySlot(result, 1);
            break;

        case MIPSInstruction_Lui:
            //m_luilist.push_front(*instruction);
            break;

        case MIPSInstruction_Ori:
        case MIPSInstruction_Addiu:
        case MIPSInstruction_Lw:
        case MIPSInstruction_Sw:
            //if(!m_luilist.empty()) MIPSDecoder::checkLui(disassembler, instruction);
            break;

        case MIPSInstruction_Break:
            return;

        default: break;
    }
}

template<MIPSDecoder::Swap_Callback Swap>
void MIPSDecoder::renderInstruction(RDContext* ctx, const RDRenderItemParams* rip)
{
    MIPSDecodedInstruction decoded;
    if(MIPSDecoder::decode<Swap>(&rip->view, &decoded) == MIPSEncoding_Unknown) return;

    MIPSDecoder::renderMnemonic(&decoded, rip);

    switch(decoded.opcode->id)
    {
        case MIPSInstruction_Lb:
        case MIPSInstruction_Lbu:
        case MIPSInstruction_Lw:
        case MIPSInstruction_Lwl:
        case MIPSInstruction_Lwr:
        case MIPSInstruction_Sb:
        case MIPSInstruction_Sh:
        case MIPSInstruction_Sw:
            MIPSDecoder::renderLoadStore(&decoded, rip);
            return;

        default: break;
    }

    if(decoded.opcode->encoding >= m_renderers.size()) return;
    auto r = m_renderers[decoded.opcode->encoding];
    r(&decoded, rip);
}

const char* MIPSDecoder::cop0reg(u32 r)
{
    if(r > COP0_REGISTERS.size()) return nullptr;
    return COP0_REGISTERS[r];
}

void MIPSDecoder::renderR(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip)
{
    switch(decoded->opcode->id)
    {
        case MIPSInstruction_Sll:
        case MIPSInstruction_Srl:
        case MIPSInstruction_Sra:
        {
            if(!MIPSDecoder::checkNop(decoded)) {
                RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rd));
                RDRenderer_Text(rip, ", ");
                RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rt));
                RDRenderer_Text(rip, ", ");
                RDRenderer_Constant(rip, RD_ToHex(decoded->instruction.r.shamt));
            }

            break;
        }

        case MIPSInstruction_Jalr:
            if(decoded->instruction.r.rd != MIPSRegister_RA) {
                RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rd));
                RDRenderer_Text(rip, ", ");
                RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rs));
            } else
                RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rs));
            break;

        case MIPSInstruction_Jr:
            RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rs));
            break;

        default:
            RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rd));
            RDRenderer_Text(rip, ", ");
            RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rs));
            RDRenderer_Text(rip, ", ");
            RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.r.rt));
            break;
    }
}

void MIPSDecoder::renderI(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip)
{
    if(decoded->opcode->id == MIPSInstruction_Lui)
    {
        RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.i.rt));
        RDRenderer_Text(rip, ", ");
        RDRenderer_Constant(rip, RD_ToHex(decoded->instruction.i.u_immediate));
        return;
    }

    if(!MIPSDecoder::checkB(decoded))
    {
        RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.i.rt));
        RDRenderer_Text(rip, ", ");
        RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.i.rs));
        RDRenderer_Text(rip, ", ");
    }

    if((decoded->opcode->category == MIPSCategory_Jump) || (decoded->opcode->category == MIPSCategory_JumpCond))
    {
        auto addr = MIPSDecoder::calcAddress(decoded, rip->address);

        if(addr) RDRenderer_Unsigned(rip, *addr);
        else RDRenderer_Text(rip, "???");
    }
    else
        RDRenderer_Constant(rip, RD_ToHex(decoded->instruction.i.u_immediate));
}

void MIPSDecoder::renderJ(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip)
{
    auto addr = MIPSDecoder::calcAddress(decoded, rip->address);

    if(addr) RDRenderer_Unsigned(rip, *addr);
    else RDRenderer_Text(rip, "???");
}

void MIPSDecoder::renderB(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip)
{
    RDRenderer_Constant(rip, RD_ToHex(decoded->instruction.b.code));
}

void MIPSDecoder::renderC(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip)
{
    RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.c.rt));
    RDRenderer_Text(rip, ", ");
    RDRenderer_Register(rip, MIPSDecoder::cop0reg(decoded->instruction.c.rd));
}

void MIPSDecoder::renderLoadStore(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip)
{
    RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.i.rt));
    RDRenderer_Text(rip, ", ");
    RDRenderer_Constant(rip, RD_ToHex(decoded->instruction.i.u_immediate));
    RDRenderer_Text(rip, "(");
    RDRenderer_Register(rip, MIPSDecoder::reg(decoded->instruction.i.rs));
    RDRenderer_Text(rip, ")");
}

void MIPSDecoder::renderMnemonic(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip)
{
    switch(decoded->opcode->id)
    {
        case MIPSInstruction_Sll:
        {
            if(MIPSDecoder::checkNop(decoded)) {
                RDRenderer_Mnemonic(rip, "nop", Theme_Nop);
                RDRenderer_Text(rip, " ");
                return;
            }

            break;
        }

        case MIPSInstruction_Beq:
        {
            if(MIPSDecoder::checkB(decoded)) {
                RDRenderer_Mnemonic(rip, "b", Theme_Jump);
                RDRenderer_Text(rip, " ");
                return;
            }

            break;
        }

        case MIPSInstruction_Mfc0:
        {
            if(MIPSDecoder::checkMTC0(decoded)) {
                RDRenderer_Mnemonic(rip, "mtc0", Theme_Default);
                RDRenderer_Text(rip, " ");
            }

            break;
        }

        default: break;
    }

    RDRenderer_Mnemonic(rip, decoded->opcode->mnemonic, Theme_Default);
    RDRenderer_Text(rip, " ");
}

bool MIPSDecoder::checkNop(const MIPSDecodedInstruction* decoded)
{
    if(decoded->opcode->id != MIPSInstruction_Sll) return false;
    if(decoded->instruction.r.rd != MIPSRegister_ZERO) return false;
    if(decoded->instruction.r.rt != MIPSRegister_ZERO) return false;
    return true;
}

bool MIPSDecoder::checkB(const MIPSDecodedInstruction* decoded)
{
    if(decoded->opcode->id != MIPSInstruction_Beq) return false;
    return decoded->instruction.i.rt == decoded->instruction.i.rs;
}

bool MIPSDecoder::checkMTC0(const MIPSDecodedInstruction* decoded)
{
    if(decoded->opcode->id != MIPSInstruction_Mfc0) return false;
    return decoded->instruction.c.rs == 0b00100;
}

//void MIPSDecoder::checkLui(RDDisassembler* disassembler, const RDInstruction* instruction)
//{
    // auto it = std::find_if(m_luilist.begin(), m_luilist.end(), [instruction](const RDInstruction& luiinstruction) {
    //     return luiinstruction.operands[0].reg == instruction->operands[1].reg;
    // });

    // if(it == m_luilist.end()) return;

    // bool pointer = false;
    // rd_address address = it->operands[1].u_value << 16;

    // switch(instruction->id)
    // {
    //     case MIPSInstruction_Ori:
    //         address |= instruction->operands[2].u_value;
    //         break;

    //     case MIPSInstruction_Addiu:
    //         address += RD_SignExt(instruction->operands[2].u_value, 16);
    //         break;

    //     case MIPSInstruction_Lw:
    //     case MIPSInstruction_Sw:
    //         pointer = true;
    //         address += RD_SignExt(instruction->operands[2].u_value, 16);
    //         break;

    //     default:
    //         return;
    // }

    // //const RDILCPU* cpu = RDDisassembler_GetILCPU(disassembler);
    // //u64 val = 0;

    // //if(RDILCPU_Read(cpu, &instruction->operands[0], &val))
    //     //rd_log(rd_tohex(instruction->address) + ": " + rd_tohex(val));

    // RDDocument* doc = RDContext_GetDocument(disassembler);

    // rd_type symboltype = SymbolType_None;
    // if(pointer) symboltype = RDDisassembler_MarkPointer(disassembler, address, instruction->address);
    // else symboltype = RDDisassembler_MarkLocation(disassembler, address, instruction->address);

    // std::stringstream ss;

    // if(!pointer && (symboltype == SymbolType_Data))
    // {
    //     const char* symbolname = RDDocument_GetSymbolName(doc, address);
    //     size_t bits = RDDisassembler_Bits(disassembler);

    //     ss << "= " << (symbolname ? symbolname : RD_ToHexBits(address, bits, false));
    //     RDDocument_AddAutoComment(doc, instruction->address, ss.str().c_str());
    // }

    // ss = { };
    // ss << "... " << RD_ToHexAuto(instruction->address);
    // RDDocument_AddAutoComment(doc, it->address, ss.str().c_str());

    // m_luilist.remove_if([&it](const RDInstruction& luiinstruction) {
    //     return it->address == luiinstruction.address;
    // });
//}

size_t MIPSDecoder::checkFormat(const MIPSInstruction* mi)
{
    if(!mi->r.op)
    {
        if((mi->b.funct == 0b001100) || (mi->b.funct == 0b001101))
            return MIPSEncoding_B;

        return MIPSEncoding_R;
    }

    if(mi->c.op == 0b010000) return MIPSEncoding_C;
    if(((mi->i.op >= 0x04) && (mi->i.op <= 0x2b)) || (mi->i.op == 0x01)) return MIPSEncoding_I;
    if((mi->j.op == 0x02) || (mi->j.op == 0x03)) return MIPSEncoding_J;
    return MIPSEncoding_Unknown;
}

std::optional<rd_address> MIPSDecoder::calcAddress(const MIPSDecodedInstruction* decoded, rd_address address)
{
    switch(decoded->opcode->encoding)
    {
        case MIPSEncoding_J: return (address & (0xF << ((sizeof(u32) * CHAR_BIT) - 4))) | (static_cast<u32>(decoded->instruction.j.target) << 2);
        case MIPSEncoding_I: return address + sizeof(MIPSInstruction) + static_cast<s32>(RD_SignExt(decoded->instruction.i.s_immediate << 2, 32));
        default: break;
    }

    return std::nullopt;
}

void rdplugin_init(RDContext*, RDPluginModule* pm)
{
    MIPSInitializeFormats();

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips32le, "MIPS32 (Little Endian)");
    mips32le.emulate = &MIPSDecoder::emulate<&RD_FromLittleEndian32>;
    mips32le.renderinstruction = &MIPSDecoder::renderInstruction<&RD_FromLittleEndian32>;
    //mips32le.rdil = &MIPSDecoder::rdil;
    mips32le.bits = 32;
    RDAssembler_Register(pm, &mips32le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips32be, "MIPS32 (Big Endian)");
    mips32be.emulate = &MIPSDecoder::emulate<&RD_FromBigEndian32>;
    mips32be.renderinstruction = &MIPSDecoder::renderInstruction<&RD_FromLittleEndian32>;
    //mips32be.rdil = &MIPSDecoder::rdil;
    mips32be.bits = 32;
    RDAssembler_Register(pm, &mips32be);
}
