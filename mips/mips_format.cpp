#include "mips_format.h"

#define MIPS_MACRO(name, type, size) { name, { { name, type, MIPSCategory_Macro, MIPSEncoding_None, MIPSVersion_None }, size } }

MIPSOpcodeArray MIPSOpcodes_I{ };
MIPSOpcodeArray MIPSOpcodes_R{ };
MIPSOpcodeArray MIPSOpcodes_J{ };
MIPSOpcodeArray MIPSOpcodes_B{ };
MIPSOpcodeArray MIPSOpcodes_C{ };

const MIPSMacroMap MIPSOpcodes_Macro = {
    MIPS_MACRO("la", MIPSMacro_La, sizeof(MIPSInstruction) * 2),
    MIPS_MACRO("lw", MIPSMacro_Lw, sizeof(MIPSInstruction) * 2),
    MIPS_MACRO("lhu", MIPSMacro_Lhu, sizeof(MIPSInstruction) * 2),
    MIPS_MACRO("sw", MIPSMacro_Sw, sizeof(MIPSInstruction) * 2),
    MIPS_MACRO("sh", MIPSMacro_Sh, sizeof(MIPSInstruction) * 2),

    MIPS_MACRO("li", MIPSMacro_Li, sizeof(MIPSInstruction)),
    MIPS_MACRO("b", MIPSMacro_B, sizeof(MIPSInstruction)),
    MIPS_MACRO("nop", MIPSMacro_Nop, sizeof(MIPSInstruction)),
    MIPS_MACRO("move", MIPSMacro_Move, sizeof(MIPSInstruction)),
    MIPS_MACRO("mtc0", MIPSMacro_Mtc0, sizeof(MIPSInstruction))
};

void MIPSInitializeFormats()
{
    MIPSOpcodes_R[0b100000] = { "add", MIPSInstruction_Add, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b100001] = { "addu", MIPSInstruction_Addu, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b100100] = { "and", MIPSInstruction_And, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b011010] = { "div", MIPSInstruction_Div, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b011011] = { "divu", MIPSInstruction_Divu, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b011000] = { "mult", MIPSInstruction_Mult, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b011001] = { "multu", MIPSInstruction_Multu, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b100111] = { "nor", MIPSInstruction_Nor, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b100101] = { "or", MIPSInstruction_Or, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b000000] = { "sll", MIPSInstruction_Sll, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b000011] = { "sra", MIPSInstruction_Sra, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b000010] = { "srl", MIPSInstruction_Srl, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b100010] = { "sub", MIPSInstruction_Sub, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b100011] = { "subu", MIPSInstruction_Subu, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b100110] = { "xor", MIPSInstruction_Xor, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b101010] = { "slt", MIPSInstruction_Slt, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b101011] = { "sltu", MIPSInstruction_Sltu, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b001000] = { "jr", MIPSInstruction_Jr, MIPSCategory_Jump, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b010000] = { "mfhi", MIPSInstruction_Mfhi, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b010010] = { "mflo", MIPSInstruction_Mflo, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b010001] = { "mthi", MIPSInstruction_Mthi, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b010011] = { "mtlo", MIPSInstruction_Mtlo, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b000100] = { "sllv", MIPSInstruction_Sllv, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b000111] = { "srav", MIPSInstruction_Srav, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b000110] = { "srlv", MIPSInstruction_Srlv, MIPSCategory_None, MIPSEncoding_R, MIPSVersion_I };
    MIPSOpcodes_R[0b001001] = { "jalr", MIPSInstruction_Jalr, MIPSCategory_Call, MIPSEncoding_R, MIPSVersion_I };

    MIPSOpcodes_I[0b001000] = { "addi", MIPSInstruction_Addi, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b001001] = { "addiu", MIPSInstruction_Addiu, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b001100] = { "andi", MIPSInstruction_Andi, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b001101] = { "ori", MIPSInstruction_Ori, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b001111] = { "lui", MIPSInstruction_Lui, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b000100] = { "beq", MIPSInstruction_Beq, MIPSCategory_JumpCond, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b000101] = { "bne", MIPSInstruction_Bne, MIPSCategory_JumpCond, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b000001] = { "bgez", MIPSInstruction_Bgez, MIPSCategory_JumpCond, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b000111] = { "bgtz", MIPSInstruction_Bgtz, MIPSCategory_JumpCond, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b000110] = { "blez", MIPSInstruction_Blez, MIPSCategory_JumpCond, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b100000] = { "lb", MIPSInstruction_Lb, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b100100] = { "lbu", MIPSInstruction_Lbu, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b100001] = { "lh", MIPSInstruction_Lh, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b100101] = { "lhu", MIPSInstruction_Lhu, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b100011] = { "lw", MIPSInstruction_Lw, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b100010] = { "lwl", MIPSInstruction_Lwl, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b100110] = { "lwr", MIPSInstruction_Lwr, MIPSCategory_Load, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b101000] = { "sb", MIPSInstruction_Sb, MIPSCategory_Store, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b101001] = { "sh", MIPSInstruction_Sh, MIPSCategory_Store, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b101011] = { "sw", MIPSInstruction_Sw, MIPSCategory_Store, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b011001] = { "lhi", MIPSInstruction_Lhi, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b011000] = { "llo", MIPSInstruction_Llo, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b001010] = { "slti", MIPSInstruction_Slti, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b001011] = { "sltiu", MIPSInstruction_Sltiu, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };
    MIPSOpcodes_I[0b001110] = { "xori", MIPSInstruction_Xori, MIPSCategory_None, MIPSEncoding_I, MIPSVersion_I };

    MIPSOpcodes_J[0b000010] = { "j", MIPSInstruction_J, MIPSCategory_Jump, MIPSEncoding_J, MIPSVersion_I };
    MIPSOpcodes_J[0b000011] = { "jal", MIPSInstruction_Jal, MIPSCategory_Call, MIPSEncoding_J, MIPSVersion_I };

    MIPSOpcodes_B[0b001100] = { "syscall", MIPSInstruction_Syscall, MIPSCategory_None, MIPSEncoding_B, MIPSVersion_I };
    MIPSOpcodes_B[0b001101] = { "break", MIPSInstruction_Break, MIPSCategory_None, MIPSEncoding_B, MIPSVersion_I };

    MIPSOpcodes_C[0b010000] = { "mfc0", MIPSInstruction_Mfc0, MIPSCategory_Load, MIPSEncoding_C, MIPSVersion_I };
}
