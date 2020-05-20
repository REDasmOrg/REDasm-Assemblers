#include "mips.h"
#include "mips_registers.h"
#include <climits>

std::array<MIPSDecoder::Callback_MIPSDecode, MIPSEncoding_Count> MIPSDecoder::m_decoders = {
    [](const MIPSInstruction*, RDInstruction*) { return false; },
    &MIPSDecoder::decodeR,
    &MIPSDecoder::decodeI,
    &MIPSDecoder::decodeJ,
};

const char* MIPSDecoder::regname(RDAssemblerPlugin*, const RDInstruction*, register_id_t r)
{
    if(r > GPR_REGISTERS.size()) return nullptr;
    return GPR_REGISTERS[r];
}

bool MIPSDecoder::decode(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction)
{
    MIPSInstruction* mi = reinterpret_cast<MIPSInstruction*>(RDBufferView_Data(view));
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
            RDDisassembler_EnqueueAddress(disassembler, instruction, instruction->operands[0].address);
            break;

        case MIPSInstruction_Beq:
        case MIPSInstruction_Bne:
        case MIPSInstruction_Bgtz:
        case MIPSInstruction_Blez:
            RDDisassembler_EnqueueAddress(disassembler, instruction, instruction->operands[2].address);
            break;

        default: break;
    }

    RDDocument* document = RDDisassembler_GetDocument(disassembler);
    RDInstruction* previnstruction = nullptr;
    bool isdelayslot = false;

    if(RDDocument_PrevInstruction(document, instruction, &previnstruction))
    {
        switch(previnstruction->type)
        {
            case InstructionType_Jump:
            case InstructionType_Call:
            case InstructionType_Ret:
                if(!HAS_FLAG(previnstruction, InstructionFlags_Conditional)) isdelayslot = true;
                break;

            default: break;
        }

        RDDocument_UnlockInstruction(document, previnstruction);
    }

    if(!isdelayslot)
        RDDisassembler_EnqueueNext(disassembler, instruction);
}

bool MIPSDecoder::decodeR(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSFormatR[mi->r.funct];
    if(!format.mnemonic) return false;
    MIPSDecoder::applyFormat(&format, instruction);

    instruction->id = format.id;
    instruction->u_data = MIPSEncoding_R;

    if(mi->r.shamt)
    {
        RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rd;
        RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rt;
        RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = mi->r.shamt;
    }
    else
    {
        switch(instruction->id)
        {
            case MIPSInstruction_Jr:
                RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rs;
                if(mi->r.rs == MIPSRegister_RA) instruction->type = InstructionType_Ret;
                break;

            default:
                RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rd;
                RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rt;
                RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->r.rs;
                break;
        }
    }

    return true;
}

bool MIPSDecoder::decodeI(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSFormatI[mi->i.op];
    if(!format.mnemonic) return false;
    MIPSDecoder::applyFormat(&format, instruction);

    instruction->id = format.id;
    instruction->u_data = MIPSEncoding_I;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->i.rs;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = mi->i.rt;

    if(IS_TYPE(instruction, InstructionType_Jump))
    {
        RDInstruction_PushOperand(instruction, OperandType_Immediate)->address = instruction->address + sizeof(MIPSInstruction) +
                                                                                 MIPSDecoder::signExtend(mi->i.s_immediate << 2, 32);
    }
    else
        RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = mi->i.u_immediate;

    return true;
}

bool MIPSDecoder::decodeJ(const MIPSInstruction* mi, RDInstruction* instruction)
{
    auto& format = MIPSFormatJ[mi->j.op];
    if(!format.mnemonic) return false;
    MIPSDecoder::applyFormat(&format, instruction);

    instruction->id = format.id;
    instruction->u_data = MIPSEncoding_J;

    u32 highbits = instruction->address & (0xF << ((sizeof(u32) * CHAR_BIT) - 4));
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = highbits | (static_cast<u32>(mi->j.target) << 2);
    return true;
}

void MIPSDecoder::applyFormat(const MIPSFormat* format, RDInstruction* instruction)
{
    RDInstruction_SetMnemonic(instruction, format->mnemonic);
    instruction->type = format->type;
    instruction->flags = format->flags;
}

size_t MIPSDecoder::checkFormat(const MIPSInstruction* mi)
{
    if(!mi->r.op) return MIPSEncoding_R;
    if((mi->i.op >= 0x04) && (mi->i.op <= 0x2b)) return MIPSEncoding_I;
    if((mi->j.op == 0x02) || (mi->j.op == 0x03)) return MIPSEncoding_J;
    return MIPSEncoding_Unknown;
}

void redasm_entry()
{
    MIPSInitializeFormats();

    RD_PLUGIN_CREATE(RDAssemblerPlugin, mips32le, "MIPS32 (Little Endian)");
    mips32le.decode = &MIPSDecoder::decode;
    mips32le.emulate = &MIPSDecoder::emulate;
    mips32le.regname = &MIPSDecoder::regname;

    RDAssembler_Register(&mips32le);
}
