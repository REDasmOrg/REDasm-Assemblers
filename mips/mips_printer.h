#pragma once

#include <redasm/plugins/assembler/printer/capstoneprinter.h>

using namespace REDasm;

class MipsPrinter : public CapstonePrinter
{
    public:
        MipsPrinter();
        String reg(const RegisterOperand& regop) const override;
        String disp(const Operand* operand) const override;
};
