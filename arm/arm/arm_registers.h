#pragma once

#include <array>
#include <rdapi/rdapi.h>

enum ARMRegisters {
    ARMRegister_R0,
    ARMRegister_R1,
    ARMRegister_R2,
    ARMRegister_R3,
    ARMRegister_R4,
    ARMRegister_R5,
    ARMRegister_R6,
    ARMRegister_R7,
    ARMRegister_R8,
    ARMRegister_R9,
    ARMRegister_R10,

    ARMRegister_FP,
    ARMRegister_IP,
    ARMRegister_SP,
    ARMRegister_LR,
    ARMRegister_PC,

    ARMRegister_Count,
};

extern std::array<const char*, ARMRegister_Count> ArmRegisters;
