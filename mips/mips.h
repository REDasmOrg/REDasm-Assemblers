#pragma once

#include <redasm/redasm.h>
#include <redasm/plugins/assembler/capstoneassembler.h>

using namespace REDasm;

class MipsAssembler: public CapstoneAssembler
{
    public:
        MipsAssembler();
        size_t bits() const override;
        void init(const AssemblerRequest &request) override;

    protected:
        Algorithm* doCreateAlgorithm(Disassembler* disassembler) const override;
        Printer* doCreatePrinter(Disassembler* disassembler) const override;
        bool decodeInstruction(const BufferView &view, Instruction* instruction) override;
        void onDecoded(Instruction* instruction) override;

    private:
        void setTargetOp0(Instruction* instruction) const;
        void setTargetOp1(Instruction* instruction) const;
        void setTargetOp2(Instruction* instruction) const;
        void checkJr(Instruction* instruction) const;
};

