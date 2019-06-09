#pragma once

#include <redasm/plugins/assembler/printer/printer.h>

using namespace REDasm;

class Chip8Printer : public Printer
{
    public:
        Chip8Printer(Disassembler* disassembler);
        std::string reg(const RegisterOperand& regop) const override;
};
