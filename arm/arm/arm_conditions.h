#pragma once

#include <string>
#include <array>
#include <rdapi/rdapi.h>
#include "arm_instruction.h"

extern std::array<const char*, 0b1111> ARMConditions;

std::string GetArmMnemonic(const ARMOpcode* opcode, size_t cond);
