#pragma once

#include <redasm/redasm.h>
#include <redasm/plugins/assembler/printer/printer.h>

using namespace REDasm;

class XtensaPrinter: public Printer
{
    public:
        XtensaPrinter();
        String reg(const RegisterOperand &regop) const override;
};
