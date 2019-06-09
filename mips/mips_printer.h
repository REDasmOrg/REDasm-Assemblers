#pragma once

#include <redasm/plugins/assembler/printer/capstoneprinter.h>

using namespace REDasm;

class MipsPrinter : public CapstonePrinter
{
    public:
        MipsPrinter(Disassembler* disassembler);
        std::string reg(const RegisterOperand& regop) const override;
        std::string disp(const Operand* operand) const override;
};
