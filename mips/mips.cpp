#include "mips.h"
#include <capstone/capstone.h>
#include <redasm/support/utils.h>
#include "mips_algorithm.h"
#include "mips_printer.h"
#include "mips_quirks.h"

MipsAssembler::MipsAssembler(): CapstoneAssembler()
{
    SET_INSTRUCTION_TYPE(MIPS_INS_NOP, InstructionType::Nop);
    SET_INSTRUCTION_TYPE(MIPS_INS_BREAK, InstructionType::Stop);
    SET_INSTRUCTION_TYPE(MIPS_INS_J, InstructionType::Jump);
    SET_INSTRUCTION_TYPE(MIPS_INS_B, InstructionType::Jump);
    SET_INSTRUCTION_TYPE(MIPS_INS_JAL, InstructionType::Call);
    SET_INSTRUCTION_TYPE(MIPS_INS_JALR, InstructionType::Call);
    SET_INSTRUCTION_TYPE(MIPS_INS_BAL, InstructionType::Call);
    SET_INSTRUCTION_TYPE(MIPS_INS_BEQZ, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BNEZ, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BNEL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BLEZ, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BLEZC, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BLEZL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BLTZL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BGTZ, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BGEZ, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BGEZC, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BGEZL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BGEZAL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BGTZL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BGEZALL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BLTZ, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BNE, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BNEL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BEQ, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BEQL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BC1F, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BC1FL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BC1TL, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_BBIT132, InstructionType::Conditional);
    SET_INSTRUCTION_TYPE(MIPS_INS_ADD, InstructionType::Add);
    SET_INSTRUCTION_TYPE(MIPS_INS_ADDI, InstructionType::Add);
    SET_INSTRUCTION_TYPE(MIPS_INS_ADDIU, InstructionType::Add);
    SET_INSTRUCTION_TYPE(MIPS_INS_ADDU, InstructionType::Add);
    SET_INSTRUCTION_TYPE(MIPS_INS_SUB, InstructionType::Sub);
    SET_INSTRUCTION_TYPE(MIPS_INS_SUBU, InstructionType::Sub);
    SET_INSTRUCTION_TYPE(MIPS_INS_MUL, InstructionType::Mul);
    SET_INSTRUCTION_TYPE(MIPS_INS_AND, InstructionType::And);
    SET_INSTRUCTION_TYPE(MIPS_INS_ANDI, InstructionType::And);
    SET_INSTRUCTION_TYPE(MIPS_INS_OR, InstructionType::Or);
    SET_INSTRUCTION_TYPE(MIPS_INS_ORI, InstructionType::Or);
    SET_INSTRUCTION_TYPE(MIPS_INS_XOR, InstructionType::Xor);
    SET_INSTRUCTION_TYPE(MIPS_INS_XORI, InstructionType::Xor);
    SET_INSTRUCTION_TYPE(MIPS_INS_SLL, InstructionType::Lsh);
    SET_INSTRUCTION_TYPE(MIPS_INS_SLLV, InstructionType::Lsh);
    SET_INSTRUCTION_TYPE(MIPS_INS_SRL, InstructionType::Rsh);
    SET_INSTRUCTION_TYPE(MIPS_INS_SRLV, InstructionType::Rsh);
    SET_INSTRUCTION_TYPE(MIPS_INS_SRAV, InstructionType::Rsh);

    REGISTER_INSTRUCTION(MIPS_INS_JR, &MipsAssembler::checkJr);
    REGISTER_INSTRUCTION(MIPS_INS_J, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_JAL, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_JALR, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_B, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_BAL, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_BC1FL, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_BC1TL, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_BC1F, &MipsAssembler::setTargetOp0);
    REGISTER_INSTRUCTION(MIPS_INS_BEQZ, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BNEZ, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BNEL, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BLEZ, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BLEZC, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BLEZL, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BLTZL, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BGTZ, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BGEZ, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BGEZC, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BGEZL, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BGEZAL, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BGEZALL, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BGTZL, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BLTZ, &MipsAssembler::setTargetOp1);
    REGISTER_INSTRUCTION(MIPS_INS_BNE, &MipsAssembler::setTargetOp2);
    REGISTER_INSTRUCTION(MIPS_INS_BNEL, &MipsAssembler::setTargetOp2);
    REGISTER_INSTRUCTION(MIPS_INS_BEQ, &MipsAssembler::setTargetOp2);
    REGISTER_INSTRUCTION(MIPS_INS_BEQL, &MipsAssembler::setTargetOp2);
    REGISTER_INSTRUCTION(MIPS_INS_BBIT132, &MipsAssembler::setTargetOp2);
}

size_t MipsAssembler::bits() const { return (this->mode() & CS_MODE_MIPS64) ? 64 : 32; }

void MipsAssembler::init(const AssemblerRequest &request)
{
    if(request.modeIs("mips32le"))
        this->open(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN);
    else if(request.modeIs("mips64le"))
        this->open(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN);
    else if(request.modeIs("mips32r6le"))
        this->open(CS_ARCH_MIPS, CS_MODE_MIPS32R6 | CS_MODE_LITTLE_ENDIAN);
    else if(request.modeIs("mips2le"))
        this->open(CS_ARCH_MIPS, CS_MODE_MIPS2 | CS_MODE_LITTLE_ENDIAN);
    else if(request.modeIs("mips3le"))
        this->open(CS_ARCH_MIPS, CS_MODE_MIPS3 | CS_MODE_LITTLE_ENDIAN);
    else if(request.modeIs("mipsmicrole"))
        this->open(CS_ARCH_MIPS, CS_MODE_MICRO | CS_MODE_LITTLE_ENDIAN);
    else
    {
        r_ctx->log("Unknown mode: " + Utils::quoted(request.mode) + ", falling back to MIPS32 Little Endian");
        this->open(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN);
    }
}

Algorithm *MipsAssembler::doCreateAlgorithm(Disassembler *disassembler) const { return new MipsAlgorithm(disassembler); }
Printer *MipsAssembler::doCreatePrinter(Disassembler *disassembler) const { return new MipsPrinter(disassembler); }

bool MipsAssembler::decodeInstruction(const BufferView &view, Instruction *instruction)
{
    if(CapstoneAssembler::decodeInstruction(view, instruction))
        return true;

    return MipsQuirks::decode(view, instruction); // Handle COP2 instructions and more
}

void MipsAssembler::onDecoded(Instruction *instruction)
{
    CapstoneAssembler::onDecoded(instruction);
    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userData());

    if(!insn)
        return;

    const cs_mips& mips = insn->detail->mips;

    for(size_t i = 0; i < mips.op_count; i++)
    {
        const cs_mips_op& op = mips.operands[i];

        if(op.type == MIPS_OP_MEM)
            instruction->disp(op.mem.base, op.mem.disp);
        else if(op.type == MIPS_OP_REG)
            instruction->reg(op.reg);
        else if(op.type == MIPS_OP_IMM)
            instruction->imm(op.imm);
    }
}

void MipsAssembler::setTargetOp0(Instruction *instruction) const { instruction->targetIdx(0); }
void MipsAssembler::setTargetOp1(Instruction *instruction) const { instruction->targetIdx(1); }
void MipsAssembler::setTargetOp2(Instruction *instruction) const { instruction->targetIdx(2); }

void MipsAssembler::checkJr(Instruction *instruction) const
{
    if(instruction->op(0)->reg.r != MIPS_REG_RA)
    {
        instruction->type() = InstructionType::Jump;
        instruction->op(0)->asTarget();
    }
    else
        instruction->type() = InstructionType::Stop;
}

REDASM_ASSEMBLER("MIPS", "Dax", "MIT", 1)
REDASM_LOAD { mips.plugin = new MipsAssembler(); return true; }
REDASM_UNLOAD { mips.plugin->release(); }
