#include "metaarm_printer.h"
#include <redasm/disassembler/disassembler.h>
#include <redasm/plugins/assembler/assembler.h>

MetaARMPrinter::MetaARMPrinter(Disassembler *disassembler): CapstonePrinter(disassembler) { }
String MetaARMPrinter::size(const Operand *operand) const { return String(); }

String MetaARMPrinter::mem(const Operand *operand) const
{
    u64 value = 0;

    if(!this->disassembler()->readAddress(operand->u_value, operand->size, &value))
        return CapstonePrinter::mem(operand);

    Symbol* symbol = this->document()->symbol(value);
    return "=" + (symbol ? symbol->name : String::hex(value, this->disassembler()->assembler()->bits()));
}
