#include "metaarm_printer.h"
#include <redasm/disassembler/disassembler.h>
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/redasm.h>

MetaARMPrinter::MetaARMPrinter(): CapstonePrinter() { }
String MetaARMPrinter::size(const Operand *operand) const { return String(); }

String MetaARMPrinter::mem(const Operand *operand) const
{
    u64 value = 0;

    if(!r_disasm->readAddress(operand->u_value, operand->size, &value))
        return CapstonePrinter::mem(operand);

    Symbol* symbol = r_doc->symbol(value);
    return "=" + (symbol ? symbol->name : String::hex(value, r_asm->bits()));
}
