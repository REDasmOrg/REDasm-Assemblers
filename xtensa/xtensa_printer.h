#pragma once

#include <unordered_map>
#include <redasm/redasm.h>
#include <redasm/plugins/assembler/printer/printer.h>

using namespace REDasm;

class XtensaPrinter: public Printer
{
    public:
        XtensaPrinter();
        String reg(const RegisterOperand &regop) const override;

    private:
        static void initSpecialRegisters();

    private:
        static std::unordered_map<u8, String> m_specialregisters;
};
