#include "x86_printer.h"

X86Printer::X86Printer(Disassembler *disassembler): CapstonePrinter(disassembler) { }

String X86Printer::loc(const Operand* op) const
{
    if(op->is(OperandType::Local))
        return "local_" + String::hex(op->loc_index);
    if(op->is(OperandType::Argument))
        return "arg_" + String::hex(op->loc_index);

    return String();
}
