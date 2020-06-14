#include "arm_conditions.h"

std::array<const char*, 0b1111> ARMConditions = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", ""
};

std::string GetArmMnemonic(const ARMOpcode* opcode, size_t cond)
{
    std::string m = opcode->mnemonic;
    if(cond < ARMConditions.size()) m += ARMConditions[cond];
    return m;
}
