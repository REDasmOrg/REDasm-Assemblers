#include "mips_algorithm.h"
#include <capstone/capstone.h>

MipsAlgorithm::MipsAlgorithm(Disassembler *disassembler): ControlFlowAlgorithm(disassembler)
{
    m_delayslotinstructions.insert(MIPS_INS_J);
    m_delayslotinstructions.insert(MIPS_INS_JAL);
    m_delayslotinstructions.insert(MIPS_INS_JR);
}

void MipsAlgorithm::onDecoded(Instruction* instruction)
{
    if(m_pendingdelayslots.find(instruction->address) != m_pendingdelayslots.end())
    {
        Algorithm::onDecoded(instruction);
        m_pendingdelayslots.erase(instruction->address);

        if(instruction->is(InstructionType::Stop))
            return;
    }

    ControlFlowAlgorithm::onDecoded(instruction);

    if(m_delayslotinstructions.find(instruction->id) != m_delayslotinstructions.end())
    {
        m_pendingdelayslots.insert(instruction->endAddress());
        this->enqueue(instruction->endAddress());
    }
}
