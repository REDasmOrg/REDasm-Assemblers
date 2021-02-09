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

    // C-Type
    MIPSInstruction_Teq, MIPSInstruction_Tge,

    // I-Type
    MIPSInstruction_Addi, MIPSInstruction_Addiu, MIPSInstruction_Andi,
    MIPSInstruction_Ori, MIPSInstruction_Lui, MIPSInstruction_Beq,
    MIPSInstruction_Bgez, MIPSInstruction_Bgtz, MIPSInstruction_Blez,
    MIPSInstruction_Bne,
    MIPSInstruction_Lb, MIPSInstruction_Lbu, MIPSInstruction_Lh,
    MIPSInstruction_Lhu, MIPSInstruction_Lw,
    MIPSInstruction_Lwl, MIPSInstruction_Lwr,
    MIPSInstruction_Sb, MIPSInstruction_Sh, MIPSInstruction_Sw,
    MIPSInstruction_Swl, MIPSInstruction_Swr,
    MIPSInstruction_Lhi, MIPSInstruction_Llo,
    MIPSInstruction_Slti, MIPSInstruction_Sltiu,

    //J-Type
    MIPSInstruction_J, MIPSInstruction_Jal,

    //B-Type
    MIPSInstruction_Break, MIPSInstruction_Syscall,

    //C0-Type
    MIPSInstruction_Mfc0, MIPSInstruction_Mtc0,

    //C2-Type
    MIPSInstruction_Mfc2, MIPSInstruction_Mtc2,
    MIPSInstruction_Cfc2, MIPSInstruction_Ctc2,

    //CLS-Type
    MIPSInstruction_Lwc1, MIPSInstruction_Swc1,
    MIPSInstruction_Lwc2, MIPSInstruction_Swc2,

    // Macro Instructions
    MIPSMacro_La, MIPSMacro_Li, MIPSMacro_Move,
    MIPSMacro_Lhu, MIPSMacro_Lw,
    MIPSMacro_Sw, MIPSMacro_Sh,
    MIPSMacro_B,
    MIPSMacro_Nop
};

#pragma pack(push, 1)
struct UNKFormat {
    unsigned : 21;
    unsigned code: 5;
    unsigned op: 6;
};

struct RFormat {
    unsigned funct: 6;
    unsigned shamt: 5;
    unsigned rd: 5;
    unsigned rt: 5;
    unsigned rs: 5;
    unsigned op: 6;
};

struct CFormat {
    unsigned funct: 6;
    unsigned code: 10;
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

struct C1IMMFormat {
    unsigned imm: 11;
    unsigned fs: 5;
    unsigned rt: 5;
    unsigned code: 5;
    unsigned op: 6;
};

struct C2ImplFormat {
    unsigned impl: 11;
    unsigned rd: 5;
    unsigned rt: 5;
    unsigned code: 5;
    unsigned op: 6;
};

struct C1SELFormat {
    unsigned sel: 3;
    unsigned : 8;
    unsigned rd: 5;
    unsigned rt: 5;
    unsigned code: 5;
    unsigned op: 6;
};

typedef C1SELFormat C0SELFormat;
typedef IFormatUnsigned CLSFormat;

union MIPSInstruction {
    u32 word;
    u16 hword[2];
    u8 bytes[4];

    UNKFormat unk;

    RFormat r;
    CFormat c;
    IFormatUnsigned i_u;
    IFormatSigned i_s;
    JFormat j;
    BFormat b;

    // Coprocessors
    CLSFormat cls;

    C0SELFormat c0sel;

    C1IMMFormat c1imm;
    C1SELFormat c1sel;

    C2ImplFormat c2impl;
};
#pragma pack(pop)

static_assert(sizeof(u32) == sizeof(MIPSInstruction));
