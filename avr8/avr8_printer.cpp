#include "avr8_printer.h"

AVR8Printer::AVR8Printer(): Printer() { }
String AVR8Printer::reg(const RegisterOperand &regop) const { return "r" + String::number(regop.r); }
