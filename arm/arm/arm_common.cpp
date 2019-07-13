#include "arm_common.h"
#include <capstone/capstone.h>
#include <redasm/disassembler/listing/listingdocumentiterator.h>
#include <redasm/redasm.h>

ARMCommonAssembler::ARMCommonAssembler(): CapstoneAssembler()
{
    SET_INSTRUCTION_TYPE(ARM_INS_ADD, InstructionType::Add);
    SET_INSTRUCTION_TYPE(ARM_INS_ADC, InstructionType::Add);
    SET_INSTRUCTION_TYPE(ARM_INS_SUB, InstructionType::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_SBC, InstructionType::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_RSB, InstructionType::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_RSC, InstructionType::Sub);
    SET_INSTRUCTION_TYPE(ARM_INS_LSL, InstructionType::Lsh);
    SET_INSTRUCTION_TYPE(ARM_INS_LSR, InstructionType::Rsh);
    SET_INSTRUCTION_TYPE(ARM_INS_ASR, InstructionType::Rsh);

    REGISTER_INSTRUCTION(ARM_INS_B, &ARMCommonAssembler::checkB);
    REGISTER_INSTRUCTION(ARM_INS_BL, &ARMCommonAssembler::checkCallT0);
    REGISTER_INSTRUCTION(ARM_INS_BLX, &ARMCommonAssembler::checkCallT0);
    REGISTER_INSTRUCTION(ARM_INS_BX, &ARMCommonAssembler::checkJumpT0);

    REGISTER_INSTRUCTION(ARM_INS_LDM, &ARMCommonAssembler::checkStop);
    REGISTER_INSTRUCTION(ARM_INS_POP, &ARMCommonAssembler::checkStop);

    REGISTER_INSTRUCTION(ARM_INS_LDR, &ARMCommonAssembler::checkStop_0);
    REGISTER_INSTRUCTION(ARM_INS_MOV, &ARMCommonAssembler::checkStop_0);
}

ARMCommonAssembler::~ARMCommonAssembler() { }
bool ARMCommonAssembler::isPC(const Operand *op) const { return op && (op->is(OperandType::Register) && this->isPC(op->reg.r)); }
bool ARMCommonAssembler::isLR(const Operand *op) const { return op && (op->is(OperandType::Register) && this->isLR(op->reg.r)); }

Symbol *ARMCommonAssembler::findTrampoline(ListingDocumentIterator *it) const
{
    const ListingItem* item = it->next();
    CachedInstruction instruction1 = r_doc->instruction(item->address());

    if(!it->hasNext())
        return nullptr;

    item = it->next();

    if(!item->is(ListingItemType::InstructionItem))
        return nullptr;

    const CachedInstruction& instruction2 = r_doc->instruction(item->address());

    if(!instruction1 || !instruction2 || instruction1->isInvalid() || instruction2->isInvalid())
        return nullptr;

    if((instruction1->mnemonic != "ldr") || (instruction2->mnemonic != "ldr"))
        return nullptr;

    if(!instruction1->op(1)->is(OperandType::Memory) || (instruction2->op(0)->reg.r != ARM_REG_PC))
        return nullptr;

    u64 target = instruction1->op(1)->u_value, importaddress = 0;

    if(!r_disasm->readAddress(target, sizeof(u32), &importaddress))
        return nullptr;

    Symbol *symbol = r_doc->symbol(target), *impsymbol = r_doc->symbol(importaddress);

    if(symbol && impsymbol)
        r_doc->lock(symbol->address, "imp." + impsymbol->name);

    return impsymbol;
}

void ARMCommonAssembler::onDecoded(Instruction* instruction)
{
    CapstoneAssembler::onDecoded(instruction);

    cs_insn* insn = reinterpret_cast<cs_insn*>(instruction->userData());
    const cs_arm& arm = insn->detail->arm;

    for(size_t i = 0; i < arm.op_count; i++)
    {
        const cs_arm_op& op = arm.operands[i];

        if(op.type == ARM_OP_MEM)
        {
            const arm_op_mem& mem = op.mem;

            if((mem.index == ARM_REG_INVALID) && ARMCommonAssembler::isPC(mem.base)) // [pc]
                instruction->mem(this->pc(instruction) + mem.disp);
            else
                instruction->disp(ARM_REGISTER(mem.base), ARM_REGISTER(mem.index), mem.scale, mem.disp);
        }
        else if(op.type == ARM_OP_REG)
            instruction->reg(op.reg);
        else if(op.type == ARM_OP_IMM)
            instruction->imm(op.imm);
    }
}

bool ARMCommonAssembler::isPC(register_id_t reg) const { return reg == ARM_REG_PC; }
bool ARMCommonAssembler::isLR(register_id_t reg) const { return reg == ARM_REG_LR; };

void ARMCommonAssembler::checkB(Instruction* instruction) const
{
    const cs_arm& arm = reinterpret_cast<cs_insn*>(instruction->userData())->detail->arm;

    if(arm.cc != ARM_CC_AL)
        instruction->type |= InstructionType::Conditional;

    instruction->targetIdx(0);
}

void ARMCommonAssembler::checkStop(Instruction* instruction) const
{
    const cs_arm& arm = reinterpret_cast<cs_insn*>(instruction->userData())->detail->arm;

    if(arm.cc != ARM_CC_AL)
        return;

    auto it = instruction->iterator();

    while(it.hasNext())
    {
        const Operand* op = variant_object<Operand>(it.next());

        if(!op->is(OperandType::Register) || !this->isPC(op->reg.r))
            continue;

        instruction->type = InstructionType::Stop;
        break;
    }
}

void ARMCommonAssembler::checkStop_0(Instruction *instruction) const
{
    const cs_arm& arm = reinterpret_cast<cs_insn*>(instruction->userData())->detail->arm;
    instruction->op(1)->size = sizeof(u32);

    if((arm.cc == ARM_CC_AL) && this->isPC(instruction->firstOperand()))
    {
        instruction->type = InstructionType::Stop;
        return;
    }
}

void ARMCommonAssembler::checkJumpT0(Instruction *instruction) const
{
    instruction->type = InstructionType::Jump;
    instruction->targetIdx(0);
}

void ARMCommonAssembler::checkCallT0(Instruction *instruction) const
{
    instruction->type = InstructionType::Call;
    instruction->targetIdx(0);
}
