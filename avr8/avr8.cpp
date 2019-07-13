#include "avr8.h"
#include "avr8_printer.h"
#include "avr8_opcodes.h"
#include <redasm/support/utils.h>

AVR8Assembler::AVR8Assembler(): Assembler()
{
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Nop_0000, InstructionType::Nop);

    SET_INSTRUCTION_TYPE(AVR8Opcodes::Break_9598, InstructionType::Stop);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Ret_9508, InstructionType::Stop);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Reti_9518, InstructionType::Stop);

    SET_INSTRUCTION_TYPE(AVR8Opcodes::Ijmp_9409, InstructionType::Jump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Eijmp_9419, InstructionType::Jump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Jmp_940c, InstructionType::Jump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Rjmp_c000, InstructionType::Jump);

    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brcc_f400, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brcs_f000, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Breq_f001, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brge_f404, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brhc_f405, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brhs_f005, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brid_f407, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brie_f007, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brlo_f000, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brlt_f004, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brmi_f002, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brne_f401, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brpl_f402, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brsh_f400, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brtc_f406, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brts_f006, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brvc_f403, InstructionType::ConditionalJump);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Brvs_f003, InstructionType::ConditionalJump);

    SET_INSTRUCTION_TYPE(AVR8Opcodes::Icall_9509, InstructionType::Call);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Eicall_9519, InstructionType::Call);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Call_940e, InstructionType::Call);
    SET_INSTRUCTION_TYPE(AVR8Opcodes::Rcall_d000, InstructionType::Call);
}

size_t AVR8Assembler::bits() const { return 16; }
Printer *AVR8Assembler::doCreatePrinter() const { return new AVR8Printer(); }

void AVR8Assembler::compileInstruction(Instruction *instruction, const AVR8Operand& avrop, size_t opindex)
{
    if(avrop.tag == AVR8Operands::BranchAddress)
        instruction->targetIdx(opindex);
}

bool AVR8Assembler::decodeInstruction(const BufferView &view, Instruction *instruction)
{
    u32 opcode = static_cast<u16>(view); // Try with 16 bits
    const AVR8Instruction* avrinstruction = AVR8Decoder::get(opcode);

    if(!avrinstruction)
        return false;

    if(avrinstruction->size != 2)
        opcode = view; // Get the complete 32-bit instruction

    instruction->id = avrinstruction->id;
    instruction->mnemonic = avrinstruction->mnemonic.c_str();
    instruction->size = avrinstruction->size;

    size_t opidx = 0;

    for(auto it = avrinstruction->operands.begin(); it != avrinstruction->operands.end(); it++, opidx++)
    {
        u32 opval = Utils::unmask(static_cast<u16>(opcode), it->mask);

        if(avrinstruction->size != 2)
            opval = view + sizeof(u16);

        this->decodeOperand(opval, instruction, *it, opidx);
    }

    return true;
}

void AVR8Assembler::decodeOperand(u32 opvalue, Instruction *instruction, const AVR8Operand &avrop, size_t opidx)
{
    u32 opres = 0;

    if(avrop.tag == AVR8Operands::BranchAddress) // Relative branch address is 7 bits, two's complement form
    {
        if(opvalue & (1 << 6)) // Check Sign
        {
            // Sign-extend to the 32-bit container
            opres = static_cast<u32>(static_cast<s32>((~opvalue + 1) & 0x7F));
            opres *= -1;
        }
        else
            opres = opvalue & 0x7F;

        opres *= 2;
        instruction->imm(static_cast<u32>(instruction->endAddress() + opres), avrop.tag);
        instruction->targetIdx(opidx);
    }
    else if(avrop.tag == AVR8Operands::RelativeAddress) // Relative address is 12 bits, two's complement form
    {
        if(opvalue & (1 << 11)) // Check Sign
        {
            // Sign-extend to the 32-bit container
            opres = static_cast<u32>(static_cast<s32>((~opvalue + 1) & 0xFFF));
            opres *= -1;
        }
        else
            opres = opvalue & 0xFFF;

        opres *= 2;
        instruction->imm(static_cast<u32>(instruction->endAddress() + opres), avrop.tag);
        instruction->targetIdx(opidx);
    }
    else if(avrop.tag == AVR8Operands::LongAbsoluteAddress)
        instruction->imm(opvalue, avrop.tag);
    else if(avrop.tag == AVR8Operands::RegisterStartR16)
        instruction->reg(opvalue + 16, avrop.tag);
    else if(avrop.tag == AVR8Operands::RegisterEvenPair)
        instruction->reg(opvalue * 2, avrop.tag);
    else if(avrop.tag == AVR8Operands::RegisterEvenPairStartR24)
        instruction->reg(24 + opvalue * 2, avrop.tag);
    else if(avrop.tag == AVR8Operands::Register)
        instruction->reg(opvalue);
    else
        instruction->cnst(opvalue, avrop.tag);
}

REDASM_ASSEMBLER("AVR8", "Dax", "MIT", 1)
REDASM_LOAD { avr8.plugin = new AVR8Assembler(); return true; }
REDASM_UNLOAD { avr8.plugin->release(); }
