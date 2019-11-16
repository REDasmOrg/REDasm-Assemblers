#include "mips_printer.h"
#include "mips_quirks.h"

MipsPrinter::MipsPrinter(): CapstonePrinter() { }

String MipsPrinter::reg(const RegisterOperand* regop) const
{
    if(regop->tag & MipsRegisterTypes::Cop2Register)
        return "$" + String::number(regop->r);

    return "$" + CapstonePrinter::reg(regop);
}

String MipsPrinter::disp(const Operand* operand) const
{
    return String::hex(operand->disp.displacement) + "(" + this->reg(&operand->disp.basestruct) + ")";
}
