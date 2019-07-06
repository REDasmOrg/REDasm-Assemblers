#pragma once

#include <redasm/plugins/assembler/printer/capstoneprinter.h>

using namespace REDasm;

class MetaARMPrinter: public CapstonePrinter
{
    public:
        MetaARMPrinter(Disassembler* disassembler);

    public:
        String size(const Operand* operand) const override;
        String mem(const Operand* operand) const override;
};
