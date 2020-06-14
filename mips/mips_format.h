#pragma once

#include "mips_instruction.h"
#include <array>

enum MIPSVersion {
    MIPSVersion_I
};

enum MIPSEncoding {
    MIPSEncoding_Unknown,
    MIPSEncoding_R, MIPSEncoding_I, MIPSEncoding_J,
    MIPSEncoding_B, MIPSEncoding_C,
    MIPSEncoding_Count
};

struct MIPSOpcode {
    const char* mnemonic;
    rd_instruction_id id;
    rd_type type;
    rd_flag flags;
    u32 version;
};

extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_R;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_I;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_J;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_B;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_C;

void MIPSInitializeFormats();
