#include "xtensa_printer.h"

std::unordered_map<u8, String> XtensaPrinter::m_specialregisters;

XtensaPrinter::XtensaPrinter(): Printer()
{
    XtensaPrinter::initSpecialRegisters();
}

String XtensaPrinter::reg(const RegisterOperand* regop) const
{
    if(regop->tag)
    {
        auto it = m_specialregisters.find(regop->r);

        if(it != m_specialregisters.end())
            return it->second;

        return "???";
    }

    return "a" + String::number(regop->r);
}

void XtensaPrinter::initSpecialRegisters()
{
    if(!m_specialregisters.empty())
        return;

    m_specialregisters[0] = "LBEG";
    m_specialregisters[1] = "LEND";
    m_specialregisters[2] = "LCOUNT";
    m_specialregisters[3] = "SAR";
    m_specialregisters[4] = "BR";
    m_specialregisters[5] = "LITBASE";
    m_specialregisters[12] = "SCOMPARE1";
    m_specialregisters[16] = "ACCLO";
    m_specialregisters[17] = "ACCHI";
    m_specialregisters[32] = "M0";
    m_specialregisters[33] = "M1";
    m_specialregisters[34] = "M2";
    m_specialregisters[35] = "M3";
    m_specialregisters[72] = "WindowBase";
    m_specialregisters[73] = "WindowStart";
    m_specialregisters[83] = "PTEVADDR";
    m_specialregisters[89] = "MMID";
    m_specialregisters[90] = "RASID";
    m_specialregisters[91] = "ITLBCFG";
    m_specialregisters[92] = "DTLBCFG";
    m_specialregisters[96] = "IBREAKENABLE";
    m_specialregisters[98] = "CACHEATTR";
    m_specialregisters[99] = "ATOMCTL";
    m_specialregisters[104] = "DDR";
    m_specialregisters[106] = "MEPC";
    m_specialregisters[107] = "MEPS";
    m_specialregisters[108] = "MESAVE";
    m_specialregisters[109] = "MESR";
    m_specialregisters[110] = "MECR";
    m_specialregisters[111] = "MEVADDR";
    m_specialregisters[128] = "IBREAKA0";
    m_specialregisters[129] = "IBREAKA1";
    m_specialregisters[144] = "DBREAKA0";
    m_specialregisters[145] = "DBREAKA1";
    m_specialregisters[160] = "DBREAKC0";
    m_specialregisters[161] = "DBREAKC1";
    m_specialregisters[177] = "EPC1";
    m_specialregisters[178] = "EPC2";
    m_specialregisters[179] = "EPC3";
    m_specialregisters[180] = "EPC4";
    m_specialregisters[181] = "EPC5";
    m_specialregisters[182] = "EPC6";
    m_specialregisters[183] = "EPC7";
    m_specialregisters[192] = "DEPC";
    m_specialregisters[194] = "EPS2";
    m_specialregisters[195] = "EPS3";
    m_specialregisters[196] = "EPS4";
    m_specialregisters[197] = "EPS5";
    m_specialregisters[198] = "EPS6";
    m_specialregisters[199] = "EPS7";
    m_specialregisters[209] = "ECXSAVE1";
    m_specialregisters[210] = "ECXSAVE2";
    m_specialregisters[211] = "ECXSAVE3";
    m_specialregisters[212] = "ECXSAVE4";
    m_specialregisters[213] = "ECXSAVE5";
    m_specialregisters[214] = "ECXSAVE6";
    m_specialregisters[215] = "ECXSAVE7";
    m_specialregisters[224] = "CPENABLE";
    m_specialregisters[226] = "INTSET";
    m_specialregisters[227] = "INTCLEAR";
    m_specialregisters[228] = "INTENABLE";
    m_specialregisters[230] = "PS";
    m_specialregisters[231] = "VECBASE";
    m_specialregisters[232] = "EXCCAUSE";
    m_specialregisters[233] = "DEBUGCAUSE";
    m_specialregisters[234] = "CCOUNT";
    m_specialregisters[235] = "PRID";
    m_specialregisters[236] = "ICOUNT";
    m_specialregisters[237] = "ICOUNTLEVEL";
    m_specialregisters[238] = "ECXVADDR";
    m_specialregisters[240] = "CCOMPARE0";
    m_specialregisters[241] = "CCOMPARE1";
    m_specialregisters[242] = "CCOMPARE2";
    m_specialregisters[244] = "MISC0";
    m_specialregisters[245] = "MISC1";
    m_specialregisters[246] = "MISC2";
    m_specialregisters[247] = "MISC3";
}
