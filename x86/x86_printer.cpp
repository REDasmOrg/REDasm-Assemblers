#include "x86_printer.h"

X86Printer::X86Printer(): CapstonePrinter() { }

String X86Printer::loc(const Operand* op) const
{
    if(REDasm::hasFlag(op, OperandFlags::Local)) return "local_" + String::hex(op->loc_index);
    if(REDasm::hasFlag(op, OperandFlags::Argument)) return "arg_" + String::hex(op->loc_index);
    return String();
}
