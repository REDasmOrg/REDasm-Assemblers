#include "metaarm_isa.h"
#include <redasm/context.h>
#include <redasm/disassembler/disassembler.h>

// https://static.docs.arm.com/ddi0406/c/DDI0406C_C_arm_architecture_reference_manual.pdf

int MetaARMAssemblerISA::classify(address_t address, const BufferView &view, Disassembler *disassembler, Assembler *armassembler)
{
    BufferView cview = view;

    while(!cview.eob())
    {
        Instruction instruction;
        instruction.address = address;
        r_ctx->statusAddress("Classifing Instruction Set", address);

        if(!armassembler->decode(cview, &instruction))
            return MetaARMAssemblerISA::Thumb;

        if(instruction.is(InstructionType::Stop) || (instruction.is(InstructionType::Jump) && !instruction.is(InstructionType::Conditional)))
            break;

        if(instruction.is(InstructionType::Branch) && !MetaARMAssemblerISA::validateBranch(&instruction, disassembler))
            return MetaARMAssemblerISA::Thumb;

        address += instruction.size;
        cview += instruction.size;
    }

    return MetaARMAssemblerISA::ARM;
}

bool MetaARMAssemblerISA::validateBranch(const Instruction* instruction, Disassembler *disassembler)
{
    ReferenceSet targets = disassembler->getTargets(instruction->address);
    auto& document = disassembler->document();

    for(address_t target : targets)
    {
        if(!document->segment(target))
            return false;
    }

    return true;
}
