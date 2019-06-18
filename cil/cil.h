#pragma once

#include <redasm/plugins/assembler/assembler.h>
#include <redasm/redasm.h>

using namespace REDasm;

class CILAssembler : public Assembler
{
    public:
        CILAssembler();
        size_t bits() const override;

    protected:
        bool decodeInstruction(const BufferView &view, Instruction* instruction) override;
};
