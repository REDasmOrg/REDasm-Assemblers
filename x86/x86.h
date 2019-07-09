#pragma once

#include <redasm/plugins/assembler/capstoneassembler.h>
#include <redasm/redasm.h>

using namespace REDasm;

class X86Assembler: public CapstoneAssembler
{
    public:
        X86Assembler();
        size_t bits() const override;
        void init(const AssemblerRequest &request) override;
        Symbol* findTrampoline(ListingDocumentIterator* it) const override;

    protected:
        Printer* doCreatePrinter(Disassembler* disassembler) const override;
        void onDecoded(Instruction* instruction) override;

    private:
        void setBranchTarget(Instruction* instruction);
        void checkLea(Instruction* instruction);
        void compareOp1(Instruction* instruction);
        s64 bpIndex(s64 disp, OperandType &type) const;
        s64 spIndex(s64 disp) const;
        bool isSP(register_id_t reg) const;
        bool isBP(register_id_t reg) const;
        bool isIP(register_id_t reg) const;
};
