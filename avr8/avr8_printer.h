#pragma once

#include <redasm/plugins/assembler/printer/printer.h>

using namespace REDasm;

class AVR8Printer: public Printer
{
    public:
        AVR8Printer(Disassembler* disassembler);
        String reg(const RegisterOperand &regop) const override;
};
