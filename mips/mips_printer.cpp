#include "mips_printer.h"
#include "mips_quirks.h"
#include <redasm/support/utils.h>

MipsPrinter::MipsPrinter(Disassembler *disassembler): CapstonePrinter(disassembler) { }

std::string MipsPrinter::reg(const RegisterOperand &regop) const
{
    if(regop.tag & MipsRegisterTypes::Cop2Register)
        return "$" + Utils::dec(regop.r);

    return "$" + CapstonePrinter::reg(regop);
}

std::string MipsPrinter::disp(const Operand *operand) const
{
    return Utils::hex(operand->disp.displacement) + "(" + this->reg(operand->disp.base) + ")";
}
