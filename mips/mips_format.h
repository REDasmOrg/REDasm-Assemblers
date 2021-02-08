#pragma once

#include "mips_instruction.h"
#include <unordered_map>
#include <string>
#include <array>

enum MIPSVersion {
    MIPSVersion_None,
    MIPSVersion_I
};

enum MIPSEncoding {
    MIPSEncoding_None,
    MIPSEncoding_R, MIPSEncoding_I, MIPSEncoding_J,
    MIPSEncoding_B,
    MIPSEncoding_C0, MIPSEncoding_C1, MIPSEncoding_C2,
    MIPSEncoding_Count
};

enum MIPSCategory {
    MIPSCategory_None,
    MIPSCategory_Macro,

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

union MIPSMacroOpCode {
    struct {
        unsigned reg: 5;

        union {
            rd_address address;
            u64 u_value;
            s64 s_value;
        };
    } regimm; // opcode reg, imm
};

struct MIPSDecodedInstruction {
    MIPSInstruction instruction;
    const MIPSOpcode* opcode;
    MIPSMacroOpCode macro;
    size_t size{sizeof(MIPSInstruction)};
};

typedef std::array<MIPSOpcode, 1 << MIPS_OP_BITS> MIPSOpcodeArray;
typedef std::pair<MIPSOpcode, size_t> MIPSMacro;
typedef std::unordered_map<std::string, MIPSMacro> MIPSMacroMap;

extern const MIPSMacroMap MIPSOpcodes_Macro;
extern MIPSOpcodeArray MIPSOpcodes_R;
extern MIPSOpcodeArray MIPSOpcodes_I;
extern MIPSOpcodeArray MIPSOpcodes_J;
extern MIPSOpcodeArray MIPSOpcodes_B;
extern MIPSOpcodeArray MIPSOpcodes_C0;
extern MIPSOpcodeArray MIPSOpcodes_C1;
extern MIPSOpcodeArray MIPSOpcodes_C2;

void MIPSInitializeFormats();
