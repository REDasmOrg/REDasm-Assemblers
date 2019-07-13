#pragma once

#include <redasm/plugins/assembler/algorithm/controlflow.h>

using namespace REDasm;

class MetaARMAlgorithm : public ControlFlowAlgorithm
{
    public:
        MetaARMAlgorithm();

    protected:
        void onEmulatedOperand(const Operand* op, const CachedInstruction& instruction, u64 value) override;
        void enqueueTarget(address_t target, const CachedInstruction& instruction) override;
        void decodeState(const State *state) override;
        void memoryState(const State* state) override;
        void pointerState(const State* state) override;
        void immediateState(const State *state) override;
};
