#pragma once

#include <redasm/plugins/assembler/algorithm/controlflow.h>
#include <set>

using namespace REDasm;

class MipsAlgorithm : public ControlFlowAlgorithm
{
    public:
        MipsAlgorithm();

    protected:
        void onDecoded(const CachedInstruction& instruction) override;

    private:
        std::set<address_t> m_pendingdelayslots;
        std::set<instruction_id_t> m_delayslotinstructions;
};
