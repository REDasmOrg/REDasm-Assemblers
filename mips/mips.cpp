#include "mips.h"
#include <capstone/capstone.h>
#include <redasm/support/utils.h>
#include "mips_algorithm.h"
#include "mips_printer.h"
#include "mips_quirks.h"

MipsAssembler::MipsAssembler(): CapstoneAssembler()
{
    CLASSIFY_INSTRUCTION(MIPS_INS_NOP, Instruction::T_Nop);
    CLASSIFY_INSTRUCTION(MIPS_INS_BREAK, Instruction::T_Stop);
    CLASSIFY_INSTRUCTION(MIPS_INS_J, Instruction::T_Jump);
    CLASSIFY_INSTRUCTION(MIPS_INS_B, Instruction::T_Jump);
    CLASSIFY_INSTRUCTION(MIPS_INS_JAL, Instruction::T_Call);
    CLASSIFY_INSTRUCTION(MIPS_INS_JALR, Instruction::T_Call);
    CLASSIFY_INSTRUCTION(MIPS_INS_BAL, Instruction::T_Call);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BEQZ, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BNEZ, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BNEL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BLEZ, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BLEZC, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BLEZL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BLTZL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BGTZ, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BGEZ, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BGEZC, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BGEZL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BGEZAL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BGTZL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BGEZALL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BLTZ, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BNE, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BNEL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BEQ, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BEQL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BC1F, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BC1FL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BC1TL, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION_F(MIPS_INS_BBIT132, Instruction::F_Conditional);
    CLASSIFY_INSTRUCTION(MIPS_INS_ADD, Instruction::T_Add);
    CLASSIFY_INSTRUCTION(MIPS_INS_ADDI, Instruction::T_Add);
    CLASSIFY_INSTRUCTION(MIPS_INS_ADDIU, Instruction::T_Add);
    CLASSIFY_INSTRUCTION(MIPS_INS_ADDU, Instruction::T_Add);
    CLASSIFY_INSTRUCTION(MIPS_INS_SUB, Instruction::T_Sub);
    CLASSIFY_INSTRUCTION(MIPS_INS_SUBU, Instruction::T_Sub);
    CLASSIFY_INSTRUCTION(MIPS_INS_MUL, Instruction::T_Mul);
    CLASSIFY_INSTRUCTION(MIPS_INS_AND, Instruction::T_And);
    CLASSIFY_INSTRUCTION(MIPS_INS_ANDI, Instruction::T_And);
    CLASSIFY_INSTRUCTION(MIPS_INS_OR, Instruction::T_Or);
    CLASSIFY_INSTRUCTION(MIPS_INS_ORI, Instruction::T_Or);
    CLASSIFY_INSTRUCTION(MIPS_INS_XOR, Instruction::T_Xor);
    CLASSIFY_INSTRUCTION(MIPS_INS_XORI, Instruction::T_Xor);
    CLASSIFY_INSTRUCTION(MIPS_INS_SLL, Instruction::T_Lsh);
    CLASSIFY_INSTRUCTION(MIPS_INS_SLLV, Instruction::T_Lsh);
    CLASSIFY_INSTRUCTION(MIPS_INS_SRL, Instruction::T_Rsh);
    CLASSIFY_INSTRUCTION(MIPS_INS_SRLV, Instruction::T_Rsh);
    CLASSIFY_INSTRUCTION(MIPS_INS_SRAV, Instruction::T_Rsh);

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
        r_ctx->log("Unknown mode: " + String(request.mode).quoted() + ", falling back to MIPS32 Little Endian");
        this->open(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN);
    }
}

Algorithm *MipsAssembler::doCreateAlgorithm() const { return new MipsAlgorithm(); }
Printer *MipsAssembler::doCreatePrinter() const { return new MipsPrinter(); }

bool MipsAssembler::decodeInstruction(const BufferView &view, Instruction *instruction)
{
    if(CapstoneAssembler::decodeInstruction(view, instruction))
        return true;

    return MipsQuirks::decode(view, instruction); // Handle COP2 instructions and more
}

void MipsAssembler::onDecoded(Instruction *instruction)
{
    CapstoneAssembler::onDecoded(instruction);
    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);

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
        instruction->type = Instruction::T_Jump;
        instruction->op(0)->asTarget();
    }
    else
        instruction->type = Instruction::T_Stop;
}

REDASM_ASSEMBLER("MIPS", "Dax", "MIT", 1)
REDASM_LOAD { mips.plugin = new MipsAssembler(); return true; }
REDASM_UNLOAD { mips.plugin->release(); }
