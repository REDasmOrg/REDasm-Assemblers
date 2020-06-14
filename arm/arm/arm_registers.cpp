#include "arm_registers.h"
#include "../common.h"

std::array<const char*, ARMRegister_Count> ArmRegisters = {
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10",
    "FP", "IP", "SP", "LR", "PC"
};
