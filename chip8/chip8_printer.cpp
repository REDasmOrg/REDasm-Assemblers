#include "chip8_printer.h"
#include "chip8_registers.h"
#include <sstream>

Chip8Printer::Chip8Printer(Disassembler *disassembler): Printer(disassembler) { }

std::string Chip8Printer::reg(const RegisterOperand &regop) const
{
    if(regop.tag == CHIP8_REG_I)
        return "i";

    if(regop.tag == CHIP8_REG_DT)
        return "dt";

    if(regop.tag == CHIP8_REG_ST)
        return "st";

    std::stringstream ss;
    ss << ((regop.tag == CHIP8_REG_K) ? "k" : "v") << std::hex << regop.r;
    return ss.str();
}
