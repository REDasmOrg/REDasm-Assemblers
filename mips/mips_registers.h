#pragma once

#include <array>

#define MIPS_GPR_COUNT 32

enum MIPSRegisters {
    MIPSRegister_ZERO, MIPSRegister_AT,
    MIPSRegister_V0, MIPSRegister_V1,
    MIPSRegister_A0, MIPSRegister_A1, MIPSRegister_A2, MIPSRegister_A3,
    MIPSRegister_T0, MIPSRegister_T1, MIPSRegister_T2, MIPSRegister_T3, MIPSRegister_T4, MIPSRegister_T5, MIPSRegister_T6, MIPSRegister_T7,
    MIPSRegister_S0, MIPSRegister_S1, MIPSRegister_S2, MIPSRegister_S3, MIPSRegister_S4, MIPSRegister_S5, MIPSRegister_S6, MIPSRegister_S7,
    MIPSRegister_T8, MIPSRegister_T9,
    MIPSRegister_K0, MIPSRegister_K1,
    MIPSRegister_GP, MIPSRegister_SP, MIPSRegister_FP, MIPSRegister_RA
};

const std::array<const char*, MIPS_GPR_COUNT> GPR_REGISTERS = {
    "$zero", "$at",
    "$v0", "$v1",
    "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9",
    "$k0", "$k1",
    "$gp", "$sp", "$fp", "$ra"
};
