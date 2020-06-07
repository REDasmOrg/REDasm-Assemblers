#include "xtensa_registers.h"

const std::unordered_map<size_t, const char*> Xtensa_SpecialRegisters = {
    { 0, "LBEG"}, { 1, "LEND"}, { 2, "LCOUNT"}, { 3, "SAR"},
    { 4, "BR"}, { 5, "LITBASE"}, { 12, "SCOMPARE1"}, { 16, "ACCLO"},
    { 17, "ACCHI"},

    { 32, "M0"}, { 33, "M1"}, { 34, "M2"}, { 35, "M3"},
    { 72, "WindowBase"}, { 73, "WindowStart"},

    { 83, "PTEVADDR"}, { 89, "MMID"}, { 90, "RASID"}, { 91, "ITLBCFG"},
    { 92, "DTLBCFG"}, { 96, "IBREAKENABLE"}, { 98, "CACHEATTR"},
    { 99, "ATOMCTL"}, { 104, "DDR"},

    { 106, "MEPC"}, { 107, "MEPS"}, { 108, "MESAVE"}, { 109, "MESR"}, { 110, "MECR"}, { 111, "MEVADDR"},

    { 128, "IBREAKA0"}, { 129, "IBREAKA1"},

    { 144, "DBREAKA0"}, { 145, "DBREAKA1"}, { 160, "DBREAKC0"}, { 161, "DBREAKC1"},

    { 177, "EPC1"}, { 178, "EPC2"}, { 179, "EPC3"}, { 180, "EPC4"},
    { 181, "EPC5"}, { 182, "EPC6"}, { 183, "EPC7"}, { 192, "DEPC"}, { 194, "EPS2"},
    { 195, "EPS3"}, { 196, "EPS4"}, { 197, "EPS5"}, { 198, "EPS6"}, { 199, "EPS7"},

    { 209, "ECXSAVE1"}, { 210, "ECXSAVE2"}, { 211, "ECXSAVE3"}, { 212, "ECXSAVE4"},
    { 213, "ECXSAVE5"}, { 214, "ECXSAVE6"}, { 215, "ECXSAVE7"},

    { 224, "CPENABLE"},

    { 226, "INTSET"}, { 227, "INTCLEAR"}, { 228, "INTENABLE"},

    { 230, "PS"}, { 231, "VECBASE"}, { 232, "EXCCAUSE"}, { 233, "DEBUGCAUSE"},
    { 234, "CCOUNT"}, { 235, "PRID"},

    { 236, "ICOUNT"}, { 237, "ICOUNTLEVEL"},

    { 238, "ECXVADDR"},

    { 240, "CCOMPARE0"}, { 241, "CCOMPARE1"}, { 242, "CCOMPARE2"},

    { 244, "MISC0"}, { 245, "MISC1"}, { 246, "MISC2"}, { 247, "MISC3"},
};
