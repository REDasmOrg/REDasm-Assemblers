#include "x86.h"
#include "x86_printer.h"
#include <redasm/support/utils.h>
#include <capstone/capstone.h>

#define X86_REGISTER(reg) ((reg == X86_REG_INVALID) ? REGISTER_INVALID : reg)

X86Assembler::X86Assembler(): CapstoneAssembler()
{
    CLASSIFY_INSTRUCTION_F(X86_INS_JA, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JAE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JB, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JBE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JCXZ, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JECXZ, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JG, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JGE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JL, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JLE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JNE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JNO, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JNP, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JNS, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JO, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JP, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_JS, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_LOOP, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_LOOPE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION_F(X86_INS_LOOPNE, InstructionFlags::Conditional);
    CLASSIFY_INSTRUCTION(X86_INS_PUSH, InstructionType::Push);
    CLASSIFY_INSTRUCTION(X86_INS_PUSHAL, InstructionType::Push);
    CLASSIFY_INSTRUCTION(X86_INS_PUSHAW, InstructionType::Push);
    CLASSIFY_INSTRUCTION(X86_INS_PUSHF, InstructionType::Push);
    CLASSIFY_INSTRUCTION(X86_INS_PUSHFD, InstructionType::Push);
    CLASSIFY_INSTRUCTION(X86_INS_PUSHFQ, InstructionType::Push);
    CLASSIFY_INSTRUCTION(X86_INS_POP, InstructionType::Pop);
    CLASSIFY_INSTRUCTION(X86_INS_POPAL, InstructionType::Pop);
    CLASSIFY_INSTRUCTION(X86_INS_POPAW, InstructionType::Pop);
    CLASSIFY_INSTRUCTION(X86_INS_POPF, InstructionType::Pop);
    CLASSIFY_INSTRUCTION(X86_INS_POPFD, InstructionType::Pop);
    CLASSIFY_INSTRUCTION(X86_INS_POPFQ, InstructionType::Pop);
    CLASSIFY_INSTRUCTION(X86_INS_HLT, InstructionType::Stop);
    CLASSIFY_INSTRUCTION(X86_INS_RET, InstructionType::Stop);
    CLASSIFY_INSTRUCTION(X86_INS_NOP, InstructionType::Nop);
    CLASSIFY_INSTRUCTION(X86_INS_MOV, InstructionType::Load);
    CLASSIFY_INSTRUCTION(X86_INS_TEST, InstructionType::Compare);

    REGISTER_INSTRUCTION(X86_INS_JA, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JAE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JB, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JBE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JCXZ, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JECXZ, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JG, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JGE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JL, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JLE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNE, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNO, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNP, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JNS, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JO, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JP, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JS, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_JMP, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_CALL, &X86Assembler::setBranchTarget);
    REGISTER_INSTRUCTION(X86_INS_LEA, &X86Assembler::checkLea);
    REGISTER_INSTRUCTION(X86_INS_CMP, &X86Assembler::compareOp1);
}

size_t X86Assembler::bits() const
{
    switch(this->mode())
    {
        case CS_MODE_16: return 16;
        case CS_MODE_64: return 64;
        default: break;
    }

    return 32;
}

void X86Assembler::init(const AssemblerRequest &request)
{
    CapstoneAssembler::init(request);

    if(request.modeIs("x86_16"))
        this->open(CS_ARCH_X86, CS_MODE_16);
    else if(request.modeIs("x86_64"))
        this->open(CS_ARCH_X86, CS_MODE_64);
    else
    {
        if(!request.modeIs("x86_32"))
            r_ctx->log("Unknown mode: " + String(request.mode).quoted() + ", falling back to x86_32");

        this->open(CS_ARCH_X86, CS_MODE_32);
    }
}

const Symbol *X86Assembler::findTrampoline(size_t index) const
{
    ListingItem item = r_doc->itemAt(index);
    if(!item.isValid()) return nullptr;
    CachedInstruction instruction = r_doc->instruction(item.address);
    if(!instruction->isJump()) return nullptr;

    auto target = r_disasm->getTarget(item.address);
    if(!target.valid) return nullptr;

    return r_doc->symbol(target);
}

Printer *X86Assembler::doCreatePrinter() const { return new X86Printer(); }

void X86Assembler::onDecoded(Instruction *instruction)
{
    CapstoneAssembler::onDecoded(instruction);

    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userdata);
    const cs_x86& x86 = insn->detail->x86;

    for(size_t i = 0; i < x86.op_count; i++)
    {
        const cs_x86_op& op = x86.operands[i];

        if(op.type == X86_OP_MEM) {
            const x86_op_mem& mem = op.mem;
            s64 locindex = -1;

            if((mem.index == X86_REG_INVALID) && mem.disp && this->isBP(mem.base)) // Check locals/arguments
            {
                OperandFlags flags = OperandFlags::None;
                locindex = this->bpIndex(mem.disp, flags);
                instruction->local(locindex, X86_REGISTER(mem.base), X86_REGISTER(mem.index), mem.disp, flags);
            }
            else if(this->isSP(mem.base)) // Check locals
            {
                locindex = this->spIndex(mem.disp);

                if(locindex != -1)
                    instruction->local(locindex, X86_REGISTER(mem.base), X86_REGISTER(mem.index), mem.disp);
                else
                    instruction->disp(X86_REGISTER(mem.base), X86_REGISTER(mem.index), mem.scale, mem.disp);
            }
            else if((mem.index == X86_REG_INVALID) && this->isIP(mem.base)) // Handle case [xip + disp]
                instruction->mem(instruction->address + instruction->size + mem.disp);
            else if((mem.index == X86_REG_INVALID) && (mem.base == X86_REG_INVALID)) // Handle case [disp]
                instruction->mem(mem.disp);
            else
                instruction->disp(X86_REGISTER(mem.base), X86_REGISTER(mem.index), mem.scale, mem.disp);
        }
        else if(op.type == X86_OP_IMM)
            instruction->imm(op.imm);
        else if(op.type == X86_OP_REG)
            instruction->reg(op.reg);
    }
}

s64 X86Assembler::bpIndex(s64 disp, OperandFlags& flags) const
{
    if(disp < 0)
    {
        flags = OperandFlags::Local;
        return -disp;
    }

    s32 size = 0;

    if(this->mode() == CS_MODE_16) size = 2;
    else if(this->mode() == CS_MODE_32) size = 4;
    else if(this->mode() == CS_MODE_64) size = 8;

    if(disp < (size * 2)) return -1;
    if(disp > 0) flags = OperandFlags::Argument;
    return disp;
}

s64 X86Assembler::spIndex(s64 disp) const { return (disp <= 0) ? -1 : disp; }

bool X86Assembler::isSP(register_id_t reg) const
{
    if(this->mode() == CS_MODE_16)
        return reg == X86_REG_SP;

    if(this->mode() == CS_MODE_32)
        return reg == X86_REG_ESP;

    if(this->mode() == CS_MODE_64)
        return reg == X86_REG_RSP;

    return false;
}

bool X86Assembler::isBP(register_id_t reg) const
{
    if(this->mode() == CS_MODE_16)
        return reg == X86_REG_BP;

    if(this->mode() == CS_MODE_32)
        return reg == X86_REG_EBP;

    if(this->mode() == CS_MODE_64)
        return reg == X86_REG_RBP;

    return false;
}

bool X86Assembler::isIP(register_id_t reg) const
{
    if(this->mode() == CS_MODE_16)
        return reg == X86_REG_IP;

    if(this->mode() == CS_MODE_32)
        return reg == X86_REG_EIP;

    if(this->mode() == CS_MODE_64)
        return reg == X86_REG_RIP;

    return false;
}

void X86Assembler::setBranchTarget(Instruction *instruction) { instruction->targetIdx(0); }

void X86Assembler::checkLea(Instruction *instruction)
{
    instruction->type = InstructionType::Load;
    Operand* op1 = instruction->op(1);
    if(!REDasm::typeIs(op1, OperandType::Memory)) return;

    op1->type = OperandType::Immediate;
}

void X86Assembler::compareOp1(Instruction *instruction)
{
    instruction->type = InstructionType::Compare;
    instruction->op(1)->checkCharacter();
}

REDASM_ASSEMBLER("x86", "Dax", "MIT", 1)
REDASM_LOAD { x86.plugin = new X86Assembler(); return true; }
REDASM_UNLOAD { x86.plugin->release(); }
