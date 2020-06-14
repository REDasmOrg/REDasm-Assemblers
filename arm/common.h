#pragma once

#include <rdapi/rdapi.h>

enum ARMISA {
    ARMISA_Arm32,
    ARMISA_Arm64,
    ARMISA_Thumb16,
    ARMISA_Thumb32,
};

enum ARMFlags: rd_flag {
    ARMFlags_None,

    ARMFlags_WriteBack  = (1 << 0),
    ARMFlags_ShiftReg   = (1 << 1),
    ARMFlags_ShiftImm   = (1 << 2),

    ARMFlags_RangeBegin = (1 << 3),
    ARMFlags_RangeEnd   = (1 << 4),

    ARMFlags_ASR        = (1 << 5),
    ARMFlags_LSL        = (1 << 6),
    ARMFlags_LSR        = (1 << 7),
    ARMFlags_ROR        = (1 << 8),
    ARMFlags_RRX        = (1 << 9),
};
