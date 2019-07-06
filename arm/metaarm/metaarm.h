#pragma once

#include <redasm/plugins/assembler/assembler.h>
#include "../arm/arm.h"
#include "../arm/arm_thumb.h"

using namespace REDasm;

class MetaARMAssembler: public Assembler, public ARMAbstractAssembler
{
    public:
        MetaARMAssembler();
        virtual ~MetaARMAssembler();
        size_t bits() const override;
        bool decode(const BufferView& view, Instruction *instruction) override;
        u64 pc(const Instruction *instruction) const override;

    protected:
        Algorithm* doCreateAlgorithm(Disassembler* disassembler) const override;
        Printer* doCreatePrinter(Disassembler* disassembler) const override;

    public:
        ARMAssembler* armAssembler();
        ARMThumbAssembler* thumbAssembler();
        bool isPC(const Operand* op) const;
        bool isLR(const Operand* op) const;
        bool isArm() const;
        bool isThumb() const;
        void switchToThumb();
        void switchToArm();

    private:
        ARMAssembler* m_armassembler;
        ARMThumbAssembler* m_thumbassembler;
        Assembler* m_assembler;
};
