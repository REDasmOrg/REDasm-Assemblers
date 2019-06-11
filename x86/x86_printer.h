#pragma once

#include <redasm/plugins/assembler/printer/capstoneprinter.h>

using namespace REDasm;

class X86Printer: public CapstonePrinter
{
    public:
        X86Printer(Disassembler *disassembler);
        virtual std::string loc(const Operand *op) const;
};
