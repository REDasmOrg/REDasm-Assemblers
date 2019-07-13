#include "metaarm_algorithm.h"
#include "metaarm.h"
#include "metaarm_isa.h"
#include <redasm/disassembler/disassembler.h>
#include <redasm/plugins/loader/loader.h>
#include <redasm/redasm.h>
#include <capstone/capstone.h>

MetaARMAlgorithm::MetaARMAlgorithm(): ControlFlowAlgorithm() { }

void MetaARMAlgorithm::onEmulatedOperand(const Operand *op, const CachedInstruction &instruction, u64 value)
{
    auto* metaarm = dynamic_cast<MetaARMAssembler*>(r_asm);

    if(metaarm->isPC(op) || metaarm->isLR(op)) // Don't generate references for PC/LR registers
        return;

    ControlFlowAlgorithm::onEmulatedOperand(op, instruction, value & 0xFFFFFFFE);
}

void MetaARMAlgorithm::enqueueTarget(address_t target, const CachedInstruction &instruction)
{
    address_t ctarget = target & 0xFFFFFFFE;
    ControlFlowAlgorithm::enqueueTarget(ctarget, instruction);
}

void MetaARMAlgorithm::decodeState(const State *state)
{
    auto* metaarm = dynamic_cast<MetaARMAssembler*>(r_asm);

    if(state->address & 0x1)
    {
        metaarm->switchToThumb();
        FORWARD_STATE_VALUE(Algorithm::DecodeState, state->address - 1, state);
        return;
    }

    int res = MetaARMAssemblerISA::classify(state->address,
                                            r_ldr->view(state->address),
                                            r_disasm,
                                            metaarm->armAssembler());

    if(res == MetaARMAssemblerISA::Thumb)
        metaarm->switchToThumb();
    else
        metaarm->switchToArm();

    ControlFlowAlgorithm::decodeState(state);
}

void MetaARMAlgorithm::memoryState(const State *state)
{
    if(state->address & 1)
        return;

    ControlFlowAlgorithm::memoryState(state);
}

void MetaARMAlgorithm::pointerState(const State *state)
{
    u64 value = 0;

    if(!r_disasm->dereference(state->address, &value))
    {
        FORWARD_STATE(Algorithm::ImmediateState, state);
        return;
    }

    if(value & 1)
        return;

    ControlFlowAlgorithm::pointerState(state);
}

void MetaARMAlgorithm::immediateState(const State *state)
{
    if(state->u_value & 1)
        return;

    ControlFlowAlgorithm::immediateState(state);
}
