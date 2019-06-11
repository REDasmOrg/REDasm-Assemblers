#include "avr8_printer.h"

AVR8Printer::AVR8Printer(Disassembler *disassembler): Printer(disassembler) { }
std::string AVR8Printer::reg(const RegisterOperand &regop) const { return "r" + std::to_string(regop.r); }
