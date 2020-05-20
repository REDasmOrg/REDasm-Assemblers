#include "mips_format.h"

std::array<MIPSFormat, 1 << MIPS_OP_BITS> MIPSFormatI{ };
std::array<MIPSFormat, 1 << MIPS_OP_BITS> MIPSFormatR{ };
std::array<MIPSFormat, 1 << MIPS_OP_BITS> MIPSFormatJ{ };

void MIPSInitializeFormats()
{
    MIPSFormatR[0b100000] = { "add", MIPSInstruction_Add, InstructionType_Add, InstructionFlags_None };
    MIPSFormatR[0b100001] = { "addu", MIPSInstruction_Addu, InstructionType_Add, InstructionFlags_None };
    MIPSFormatR[0b100100] = { "and", MIPSInstruction_And, InstructionType_And, InstructionFlags_None };
    MIPSFormatR[0b011010] = { "div", MIPSInstruction_Div, InstructionType_Div, InstructionFlags_None };
    MIPSFormatR[0b011011] = { "divu", MIPSInstruction_Divu, InstructionType_Div, InstructionFlags_None };
    MIPSFormatR[0b011000] = { "mult", MIPSInstruction_Mult, InstructionType_Mul, InstructionFlags_None };
    MIPSFormatR[0b011001] = { "multu", MIPSInstruction_Multu, InstructionType_Mul, InstructionFlags_None };
    MIPSFormatR[0b100111] = { "nor", MIPSInstruction_Nor, InstructionType_None, InstructionFlags_None };
    MIPSFormatR[0b100101] = { "or", MIPSInstruction_Or, InstructionType_Or, InstructionFlags_None };
    MIPSFormatR[0b000000] = { "sll", MIPSInstruction_Sll, InstructionType_Lsh, InstructionFlags_None };
    MIPSFormatR[0b000011] = { "sra", MIPSInstruction_Sra, InstructionType_Rsh, InstructionFlags_None };
    MIPSFormatR[0b000010] = { "srl", MIPSInstruction_Srl, InstructionType_Rsh, InstructionFlags_None };
    MIPSFormatR[0b100010] = { "sub", MIPSInstruction_Sub, InstructionType_Sub, InstructionFlags_None };
    MIPSFormatR[0b100011] = { "subu", MIPSInstruction_Subu, InstructionType_Sub, InstructionFlags_None };
    MIPSFormatR[0b100110] = { "xor", MIPSInstruction_Xor, InstructionType_Xor, InstructionFlags_None };
    MIPSFormatR[0b101010] = { "slt", MIPSInstruction_Slt, InstructionType_Compare, InstructionFlags_None };
    MIPSFormatR[0b101001] = { "sltu", MIPSInstruction_Sltu, InstructionType_Compare, InstructionFlags_None };
    MIPSFormatR[0b001000] = { "jr", MIPSInstruction_Jr, InstructionType_Jump, InstructionFlags_None };
    MIPSFormatR[0b010000] = { "mfhi", MIPSInstruction_Mfhi, InstructionType_None, InstructionFlags_None };
    MIPSFormatR[0b010010] = { "mflo", MIPSInstruction_Mflo, InstructionType_None, InstructionFlags_None };
    MIPSFormatR[0b010001] = { "mthi", MIPSInstruction_Mthi, InstructionType_None, InstructionFlags_None };
    MIPSFormatR[0b010011] = { "mtlo", MIPSInstruction_Mtlo, InstructionType_None, InstructionFlags_None };
    MIPSFormatR[0b000100] = { "sllv", MIPSInstruction_Sllv, InstructionType_Lsh, InstructionFlags_None };
    MIPSFormatR[0b000111] = { "srav", MIPSInstruction_Srav, InstructionType_Rsh, InstructionFlags_None };
    MIPSFormatR[0b000110] = { "srlv", MIPSInstruction_Srlv, InstructionType_Rsh, InstructionFlags_None };
    MIPSFormatR[0b001110] = { "xori", MIPSInstruction_Xori, InstructionType_Xor, InstructionFlags_None };
    MIPSFormatR[0b001001] = { "jalr", MIPSInstruction_Jalr, InstructionType_Call, InstructionFlags_None };

    MIPSFormatI[0b001000] = { "addi", MIPSInstruction_Addi, InstructionType_Add, InstructionFlags_None };
    MIPSFormatI[0b001001] = { "addiu", MIPSInstruction_Addiu, InstructionType_Add, InstructionFlags_None };
    MIPSFormatI[0b001100] = { "andi", MIPSInstruction_Andi, InstructionType_And, InstructionFlags_None };
    MIPSFormatI[0b001101] = { "ori", MIPSInstruction_Ori, InstructionType_Or, InstructionFlags_None };
    MIPSFormatI[0b001111] = { "lui", MIPSInstruction_Lui, InstructionType_Load, InstructionFlags_None };
    MIPSFormatI[0b000100] = { "beq", MIPSInstruction_Beq, InstructionType_Jump, InstructionFlags_Conditional };
    MIPSFormatI[0b000111] = { "bgtz", MIPSInstruction_Bgtz, InstructionType_Jump, InstructionFlags_Conditional };
    MIPSFormatI[0b000110] = { "blez", MIPSInstruction_Blez, InstructionType_Jump, InstructionFlags_Conditional };
    MIPSFormatI[0b000101] = { "bne", MIPSInstruction_Bne, InstructionType_Jump, InstructionFlags_Conditional };
    MIPSFormatI[0b100000] = { "lb", MIPSInstruction_Lb, InstructionType_Load, InstructionFlags_None };
    MIPSFormatI[0b100100] = { "lbu", MIPSInstruction_Lbu, InstructionType_Load, InstructionFlags_None };
    MIPSFormatI[0b100001] = { "lh", MIPSInstruction_Lh, InstructionType_Load, InstructionFlags_None };
    MIPSFormatI[0b100101] = { "lhu", MIPSInstruction_Lhu, InstructionType_Load, InstructionFlags_None };
    MIPSFormatI[0b100011] = { "lw", MIPSInstruction_Lw, InstructionType_Load, InstructionFlags_None };
    MIPSFormatI[0b101000] = { "sb", MIPSInstruction_Sb, InstructionType_Store, InstructionFlags_None };
    MIPSFormatI[0b101001] = { "sh", MIPSInstruction_Sh, InstructionType_Store, InstructionFlags_None };
    MIPSFormatI[0b101011] = { "sw", MIPSInstruction_Sw, InstructionType_Store, InstructionFlags_None };
    MIPSFormatI[0b011001] = { "lhi", MIPSInstruction_Lhi, InstructionType_None, InstructionFlags_None };
    MIPSFormatI[0b011000] = { "llo", MIPSInstruction_Llo, InstructionType_None, InstructionFlags_None };
    MIPSFormatI[0b001010] = { "slti", MIPSInstruction_Slti, InstructionType_Compare, InstructionFlags_None };
    MIPSFormatI[0b001001] = { "sltiu", MIPSInstruction_Sltiu, InstructionType_Compare, InstructionFlags_None };

    MIPSFormatJ[0b000010] = { "j", MIPSInstruction_J, InstructionType_Jump, InstructionFlags_None };
    MIPSFormatJ[0b000011] = { "jal", MIPSInstruction_Jal, InstructionType_Call, InstructionFlags_None };
}
