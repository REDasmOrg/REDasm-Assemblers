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

enum MIPSCategory {
    MIPSCategory_None,
    MIPSCategory_Load,
    MIPSCategory_Store,
    MIPSCategory_Jump,
    MIPSCategory_JumpCond,
    MIPSCategory_Call,
    MIPSCategory_Ret,
};

struct MIPSOpcode {
    const char* mnemonic;
    u32 id;
    rd_type category;
    rd_type encoding;
    u32 version;
};

extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_R;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_I;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_J;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_B;
extern std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodes_C;

void MIPSInitializeFormats();
