#pragma once

#define ARM_REGISTER(reg) ((reg == ARM_REG_INVALID) ? REGISTER_INVALID : reg)

#include <redasm/plugins/assembler/capstoneassembler.h>

using namespace REDasm;

class ARMAbstractAssembler
{
    public:
        virtual ~ARMAbstractAssembler() { }
        virtual u64 pc(const Instruction* instruction) const = 0;
};

class ARMCommonAssembler: public CapstoneAssembler, public ARMAbstractAssembler
{
    public:
        ARMCommonAssembler();
        virtual ~ARMCommonAssembler();
        bool isPC(const Operand* op) const;
        bool isLR(const Operand* op) const;
        Symbol* findTrampoline(ListingDocumentIterator* it) const override;

    protected:
        void onDecoded(Instruction *instruction) override;

    private:
        bool isPC(register_id_t reg) const;
        bool isLR(register_id_t reg) const;
        void checkB(Instruction *instruction) const;
        void checkStop(Instruction *instruction) const;
        void checkStop_0(Instruction* instruction) const;
        void checkJumpT0(Instruction* instruction) const;
        void checkCallT0(Instruction* instruction) const;
};
