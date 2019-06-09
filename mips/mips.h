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
        bool decodeInstruction(const BufferView &view, const InstructionPtr &instruction) override;
        void onDecoded(const InstructionPtr &instruction) override;

    private:
        void setTargetOp0(const InstructionPtr& instruction) const;
        void setTargetOp1(const InstructionPtr& instruction) const;
        void setTargetOp2(const InstructionPtr& instruction) const;
        void checkJr(const InstructionPtr& instruction) const;
};

