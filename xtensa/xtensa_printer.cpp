#include "xtensa_printer.h"

XtensaPrinter::XtensaPrinter(): Printer() { }
String XtensaPrinter::reg(const RegisterOperand &regop) const { return "a" + String::number(regop.r); }
