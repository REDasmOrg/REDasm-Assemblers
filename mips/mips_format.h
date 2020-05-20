#pragma once

#include "mips_instruction.h"
#include <array>

struct MIPSFormat {
    const char* mnemonic;
    instruction_id_t id;
    type_t type;
    flag_t flags;
};

extern std::array<MIPSFormat, 1 << MIPS_OP_BITS> MIPSFormatR;
extern std::array<MIPSFormat, 1 << MIPS_OP_BITS> MIPSFormatI;
extern std::array<MIPSFormat, 1 << MIPS_OP_BITS> MIPSFormatJ;

void MIPSInitializeFormats();
