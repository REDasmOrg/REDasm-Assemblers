#include "x86_printer.h"
#include <redasm/support/utils.h>

X86Printer::X86Printer(Disassembler *disassembler): CapstonePrinter(disassembler) { }

std::string X86Printer::loc(const Operand* op) const
{
    if(op->is(OperandType::Local))
        return "local_" + Utils::hex(op->loc_index);
    if(op->is(OperandType::Argument))
        return "arg_" + Utils::hex(op->loc_index);

    return std::string();
}
