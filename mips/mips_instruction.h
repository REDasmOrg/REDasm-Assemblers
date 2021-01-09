#pragma once

#include <rdapi/rdapi.h>

#define MIPS_OP_BITS 6

enum MIPSInstructionId {
    MIPSInstruction_Invalid,

    // R-Type
    MIPSInstruction_Add, MIPSInstruction_Addu, MIPSInstruction_And,
    MIPSInstruction_Div, MIPSInstruction_Divu, MIPSInstruction_Mult,
    MIPSInstruction_Multu, MIPSInstruction_Nor, MIPSInstruction_Or,
    MIPSInstruction_Sll, MIPSInstruction_Sra, MIPSInstruction_Srl,
    MIPSInstruction_Sub, MIPSInstruction_Subu, MIPSInstruction_Xor,
    MIPSInstruction_Slt, MIPSInstruction_Sltu, MIPSInstruction_Jr,
    MIPSInstruction_Mfhi, MIPSInstruction_Mflo, MIPSInstruction_Mthi,
    MIPSInstruction_Mtlo, MIPSInstruction_Sllv, MIPSInstruction_Srav,
    MIPSInstruction_Srlv, MIPSInstruction_Xori, MIPSInstruction_Jalr,

    // I-Type
    MIPSInstruction_Addi, MIPSInstruction_Addiu, MIPSInstruction_Andi,
    MIPSInstruction_Ori, MIPSInstruction_Lui, MIPSInstruction_Beq,
    MIPSInstruction_Bgez, MIPSInstruction_Bgtz, MIPSInstruction_Blez,
    MIPSInstruction_Bne,
    MIPSInstruction_Lb, MIPSInstruction_Lbu, MIPSInstruction_Lh,
    MIPSInstruction_Lhu, MIPSInstruction_Lw,
    MIPSInstruction_Lwl, MIPSInstruction_Lwr,
    MIPSInstruction_Sb, MIPSInstruction_Sh, MIPSInstruction_Sw,
    MIPSInstruction_Lhi, MIPSInstruction_Llo,
    MIPSInstruction_Slti, MIPSInstruction_Sltiu,

    //J-Type
    MIPSInstruction_J, MIPSInstruction_Jal,

    //B-Type
    MIPSInstruction_Break, MIPSInstruction_Syscall,

    //C-Type
    MIPSInstruction_Mfc0, MIPSInstruction_Mtc0,

    // Macro Instructions
    MIPSInstruction_B, MIPSInstruction_Bgezal, MIPSInstruction_Bltz, MIPSInstruction_Bltzal,
    MIPSInstruction_Nop
};

#pragma pack(push, 1)
struct RFormat {
    unsigned funct: 6;
    unsigned shamt: 5;
    unsigned rd: 5;
    unsigned rt: 5;
    unsigned rs: 5;
    unsigned op: 6;
};

struct IFormatUnsigned {
    unsigned immediate: 16;
    unsigned rt: 5;
    unsigned rs: 5;
    unsigned op: 6;
};

struct IFormatSigned {
    signed immediate: 16;
    unsigned rt: 5;
    unsigned rs: 5;
    unsigned op: 6;
};

struct JFormat {
    unsigned target: 26;
    unsigned op: 6;
};

struct BFormat {
    unsigned funct: 6;
    unsigned code: 20;
    unsigned op: 6;
};

struct CFormat {
    unsigned imm: 11;
    unsigned rd: 5;
    unsigned rt: 5;
    unsigned rs: 5;
    unsigned op: 6;
};

union MIPSInstruction {
    u32 word;
    u16 hword[2];
    u8 bytes[4];

    RFormat r;
    IFormatUnsigned i_u;
    IFormatSigned i_s;
    JFormat j;
    BFormat b;
    CFormat c;
};
#pragma pack(pop)

static_assert(sizeof(u32) == sizeof(MIPSInstruction));
