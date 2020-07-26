#include "mips.h"
#include "mips_registers.h"
#include <algorithm>
#include <sstream>
#include <climits>

std::forward_list<RDInstruction> MIPSDecoder::m_luilist;
std::unordered_map<rd_address, rd_address> MIPSDecoder::m_delayslots;

std::array<MIPSDecoder::Callback_MIPSDecode, MIPSEncoding_Count> MIPSDecoder::m_decoders = {
    [](const MIPSInstruction*, RDInstruction*) { return false; },
    &MIPSDecoder::decodeR,
    &MIPSDecoder::decodeI,
    &MIPSDecoder::decodeJ,
    &MIPSDecoder::decodeB,
    &MIPSDecoder::decodeC,
};

const char* MIPSDecoder::regname(RDAssemblerPlugin*, const RDInstruction*, const RDOperand* op, rd_register_id r)
{
    if(op->u_data & MIPSOperand_Cop0)
    {
        if(r > COP0_REGISTERS.size()) return nullptr;
        return COP0_REGISTERS[r];
    }

    if(r > GPR_REGISTERS.size()) return nullptr;
    return GPR_REGISTERS[r];
}

template<u32 (*Swap)(u32)> bool MIPSDecoder::decode(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction)
{
    if(RDBufferView_Size(view) < sizeof(u32)) return false;

    u32 word = Swap(*reinterpret_cast<u32*>(RDBufferView_Data(view)));
    MIPSInstruction* mi = reinterpret_cast<MIPSInstruction*>(reinterpret_cast<u32*>(&word));
    instruction->size = sizeof(MIPSInstruction);

    size_t f = MIPSDecoder::checkFormat(mi);
    return (f < m_decoders.size()) ? m_decoders[f](mi, instruction) : false;
}

void MIPSDecoder::emulate(const RDAssemblerPlugin*, RDDisassembler* disassembler, const RDInstruction* instruction)
{
    switch(instruction->id)
    {
        case MIPSInstruction_J:
        case MIPSInstruction_Jal:
        case MIPSInstruction_Jalr:
        case MIPSInstruction_Jr:
        case MIPSInstruction_B:
        case MIPSInstruction_Beq:
        case MIPSInstruction_Bne:
        case MIPSInstruction_Bgez:
        case MIPSInstruction_Bgtz:
        case MIPSInstruction_Blez:
            m_delayslots[RDInstruction_NextAddress(instruction)] = instruction->address; // Process branch later...
            break;

        case MIPSInstruction_Lui:
            m_luilist.push_front(*instruction);
            break;

        case MIPSInstruction_Ori:
        case MIPSInstruction_Addiu:
        case MIPSInstruction_Lw:
        case MIPSInstruction_Sw:
            if(!m_luilist.empty()) MIPSDecoder::checkLui(disassembler, instruction);
            break;

        case MIPSInstruction_Break:
            return;

        default: break;
    }

    auto it = m_delayslots.find(instruction->address);

    if(it != m_delayslots.end())
    {
        RDDocument* document = RDDisassembler_GetDocument(disassembler);
        InstructionLock branchinstruction(document, it->second);
        if(!branchinstruction) return;

        MIPSDecoder::processDelaySlot(disassembler, *branchinstruction, instruction);
        if(branchinstruction->id == MIPSInstruction_Jr) m_luilist.clear();
        if(IS_TYPE(branchinstruction, InstructionType_Jump) || IS_TYPE(branchinstruction, InstructionType_Ret)) return;
    }

    RDDisassembler_Next(disassembler, instruction);
}

bool MIPSDecoder::render(const RDAssemblerPlugin*, RDRenderItemParams* rip)
{
    if(rip->type != RendererItemType_Instruction) return false;

    switch(rip->instruction->id)
    {
        case MIPSInstruction_Lb:
        case MIPSInstruction_Lbu:
        case MIPSInstruction_Lw:
        case MIPSInstruction_Lwl:
        case MIPSInstruction_Lwr:
        case MIPSInstruction_Sb:
        case MIPSInstruction_Sh:
        case MIPSInstruction_Sw:
            break;

        default: return false;
    }

    RDRenderer_Prologue(rip);
    RDRenderer_Mnemonic(rip);
    RDRenderer_Register(rip, &rip->instruction->operands[0], rip->instruction->operands[0].reg);
    RDRenderer_Text(rip, ", ");
    RDRendererItem_Push(rip->rendereritem, RD_ToHexBits(rip->instruction->operands[2].s_value, 16, false), "immediate_fg", nullptr);
    RDRenderer_Text(rip, "(");
    RDRenderer_Register(rip, &rip->instruction->operands[1], rip->instruction->operands[1].reg);
    RDRenderer_Text(rip, ")");
    return true;
}

void MIPSDecoder::rdil(const RDAssemblerPlugin*, const RDInstruction* instruction, RDInstruction** rdil)
{
    switch(instruction->id)
    {
        case MIPSInstruction_Nop:
            RDIL_EmitNOP(*rdil);
            break;

        case MIPSInstruction_Lui:
            RDIL_EmitCOPY(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            RDIL_SetValue(*rdil, 1, instruction->operands[1].u_value << 16);
            break;

        case MIPSInstruction_Ori:
            RDIL_EmitOR(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            RDIL_SetOperand(*rdil, 1, &instruction->operands[1]);
            RDIL_SetOperand(*rdil, 2, &instruction->operands[2]);
            break;

        case MIPSInstruction_Addu:
        case MIPSInstruction_Addiu:
            RDIL_EmitADD(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            RDIL_SetOperand(*rdil, 1, &instruction->operands[1]);
            RDIL_SetOperand(*rdil, 2, &instruction->operands[2]);
            break;

        case MIPSInstruction_J:
            RDIL_EmitJMP(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            break;

        default:
            break;
    }
}

bool MIPSDecoder::decodeR(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSOpcodes_R[mi->r.funct];
    if(!format.mnemonic) return false;
    MIPSDecoder::applyFormat(&format, instruction);

    instruction->u_data = MIPSEncoding_R;

    switch(instruction->id)
    {
        case MIPSInstruction_Sll:
        case MIPSInstruction_Srl:
        case MIPSInstruction_Sra:
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rd;
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rt;
            RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = mi->r.shamt;
            if(instruction->id == MIPSInstruction_Sll) MIPSDecoder::checkNop(instruction);
            break;

        case MIPSInstruction_Jalr:
            if(mi->r.rd != MIPSRegister_RA) {
                RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rd;
                RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rs;
            } else
                RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rs;
            break;

        case MIPSInstruction_Jr:
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rs;
            if(mi->r.rs == MIPSRegister_RA) instruction->type = InstructionType_Ret;
            break;

        default:
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rd;
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rs;
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rt;
            break;
    }

    return true;
}

bool MIPSDecoder::decodeI(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSOpcodes_I[mi->i.op];
    if(!format.mnemonic) return false;
    MIPSDecoder::applyFormat(&format, instruction);

    instruction->u_data = MIPSEncoding_I;

    switch(instruction->id)
    {
        case MIPSInstruction_Lui:
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->i.rt;
            RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = mi->i.u_immediate;
            return true;

        default: break;
    }

    if((instruction->id == MIPSInstruction_Beq) && (mi->i.rt == mi->i.rs)) // BEQ -> B
    {
        instruction->id = MIPSInstruction_B;
        instruction->flags &= ~InstructionFlags_Conditional;
        RDInstruction_SetMnemonic(instruction, "b");
    }
    else
    {
        RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->i.rt;
        RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->i.rs;
    }

    if(IS_TYPE(instruction, InstructionType_Jump))
    {
        RDInstruction_PushOperand(instruction, OperandType_Immediate)->address = instruction->address + sizeof(MIPSInstruction) +
                                                                                 static_cast<s32>(RD_SignExt(mi->i.s_immediate << 2, 32));
    }
    else
        RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = mi->i.u_immediate;

    return true;
}

bool MIPSDecoder::decodeJ(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSOpcodes_J[mi->j.op];
    if(!format.mnemonic) return false;
    MIPSDecoder::applyFormat(&format, instruction);

    instruction->u_data = MIPSEncoding_J;

    u32 highbits = instruction->address & (0xF << ((sizeof(u32) * CHAR_BIT) - 4));
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = highbits | (static_cast<u32>(mi->j.target) << 2);
    return true;
}

bool MIPSDecoder::decodeB(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSOpcodes_B[mi->b.funct];
    if(!format.mnemonic) return false;
    MIPSDecoder::applyFormat(&format, instruction);

    instruction->u_data = MIPSEncoding_B;

    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = mi->b.code;
    return true;
}

bool MIPSDecoder::decodeC(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSOpcodes_C[mi->c.op];
    if(!format.mnemonic) return false;

    if(mi->c.rs == 0b00100)
    {
        RDInstruction_SetMnemonic(instruction, "mtc0");
        instruction->id = MIPSInstruction_Mtc0;
        instruction->type = InstructionType_Store;
    }
    else
        MIPSDecoder::applyFormat(&format, instruction);

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->c.rt;

    auto* op = RDInstruction_PushOperand(instruction, OperandType_Register);
    op->reg = mi->c.rd;
    op->u_data = MIPSOperand_Cop0;

    return true;
}

bool MIPSDecoder::checkNop(RDInstruction* instruction)
{
    //if(!IS_TYPE(instruction, MIPSInstruction_Sll)) return false;

    if(instruction->operands[0].reg != MIPSRegister_ZERO) return false;
    if(instruction->operands[1].reg != MIPSRegister_ZERO) return false;

    RDInstruction_ClearOperands(instruction);
    RDInstruction_SetMnemonic(instruction, "nop");
    instruction->id = MIPSInstruction_Nop;
    instruction->type = InstructionType_Nop;
    instruction->flags = InstructionType_None;
    return true;
}

void MIPSDecoder::applyFormat(const MIPSOpcode* format, RDInstruction* instruction)
{
    RDInstruction_SetMnemonic(instruction, format->mnemonic);
    instruction->id = format->id;
    instruction->type = format->type;
    instruction->flags = format->flags;
}

void MIPSDecoder::processDelaySlot(RDDisassembler* disassembler, const RDInstruction* branchinstruction, const RDInstruction* delayslotinstruction)
{
    switch(branchinstruction->id)
    {
        case MIPSInstruction_B:
        case MIPSInstruction_J:
            RDDisassembler_Branch(disassembler, branchinstruction->operands[0].address, branchinstruction);
            break;

        case MIPSInstruction_Jal:
            RDDisassembler_Branch(disassembler, branchinstruction->operands[0].address, branchinstruction);
            RDDisassembler_Continue(disassembler, RDInstruction_NextAddress(delayslotinstruction), branchinstruction);
            break;

        case MIPSInstruction_Beq:
        case MIPSInstruction_Bne:
        case MIPSInstruction_Bgez:
        case MIPSInstruction_Bgtz:
        case MIPSInstruction_Blez:
            RDDisassembler_Branch(disassembler, branchinstruction->operands[2].address, branchinstruction);
            RDDisassembler_Continue(disassembler, RDInstruction_NextAddress(delayslotinstruction), branchinstruction);
            break;

        default: break;
    }
}

void MIPSDecoder::checkLui(RDDisassembler* disassembler, const RDInstruction* instruction)
{
    auto it = std::find_if(m_luilist.begin(), m_luilist.end(), [instruction](const RDInstruction& luiinstruction) {
        return luiinstruction.operands[0].reg == instruction->operands[1].reg;
    });

    if(it == m_luilist.end()) return;

    bool pointer = false;
    rd_address address = it->operands[1].u_value << 16;

    switch(instruction->id)
    {
        case MIPSInstruction_Ori:
            address |= instruction->operands[2].u_value;
            break;

        case MIPSInstruction_Addiu:
            address += RD_SignExt(instruction->operands[2].u_value, 16);
            break;

        case MIPSInstruction_Lw:
        case MIPSInstruction_Sw:
            pointer = true;
            address += RD_SignExt(instruction->operands[2].u_value, 16);
            break;

        default:
            return;
    }

    //const RDILCPU* cpu = RDDisassembler_GetILCPU(disassembler);
    //u64 val = 0;

    //if(RDILCPU_Read(cpu, &instruction->operands[0], &val))
        //rd_log(rd_tohex(instruction->address) + ": " + rd_tohex(val));

    RDDocument* doc = RDDisassembler_GetDocument(disassembler);

    rd_type symboltype = SymbolType_None;
    if(pointer) symboltype = RDDisassembler_MarkPointer(disassembler, address, instruction->address);
    else symboltype = RDDisassembler_MarkLocation(disassembler, address, instruction->address);

    std::stringstream ss;

    if(!pointer && (symboltype == SymbolType_Data))
    {
        const char* symbolname = RDDocument_GetSymbolName(doc, address);
        size_t bits = RDDisassembler_Bits(disassembler);

        ss << "= " << (symbolname ? symbolname : RD_ToHexBits(address, bits, false));
        RDDocument_AddAutoComment(doc, instruction->address, ss.str().c_str());
    }

    ss = { };
    ss << "... " << RD_ToHexAuto(instruction->address);
    RDDocument_AddAutoComment(doc, it->address, ss.str().c_str());

    m_luilist.remove_if([&it](const RDInstruction& luiinstruction) {
        return it->address == luiinstruction.address;
    });
}

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

void redasm_entry()
{
    MIPSInitializeFormats();

    RD_PLUGIN_CREATE(RDAssemblerPlugin, mips32le, "MIPS32 (Little Endian)");
    mips32le.decode = &MIPSDecoder::decode<&RD_FromLittleEndian32>;
    mips32le.emulate = &MIPSDecoder::emulate;
    mips32le.render = &MIPSDecoder::render;
    mips32le.regname = &MIPSDecoder::regname;
    mips32le.rdil = &MIPSDecoder::rdil;
    mips32le.bits = 32;
    RDAssembler_Register(&mips32le);

    RD_PLUGIN_CREATE(RDAssemblerPlugin, mips32be, "MIPS32 (Big Endian)");
    mips32be.decode = &MIPSDecoder::decode<&RD_FromBigEndian32>;
    mips32be.emulate = &MIPSDecoder::emulate;
    mips32be.regname = &MIPSDecoder::regname;
    mips32be.render = &MIPSDecoder::render;
    mips32be.rdil = &MIPSDecoder::rdil;
    mips32be.bits = 32;
    RDAssembler_Register(&mips32be);
}
