#pragma once

#include <array>

enum MIPSOperandFlags {
    MIPSOperand_None,
    MIPSOperand_Cop0,
    MIPSOperand_Cop1,
    MIPSOperand_Cop2,
};

enum MIPSRegisters {
    MIPSRegister_ZERO, MIPSRegister_AT,
    MIPSRegister_V0, MIPSRegister_V1,
    MIPSRegister_A0, MIPSRegister_A1, MIPSRegister_A2, MIPSRegister_A3,
    MIPSRegister_T0, MIPSRegister_T1, MIPSRegister_T2, MIPSRegister_T3, MIPSRegister_T4, MIPSRegister_T5, MIPSRegister_T6, MIPSRegister_T7,
    MIPSRegister_S0, MIPSRegister_S1, MIPSRegister_S2, MIPSRegister_S3, MIPSRegister_S4, MIPSRegister_S5, MIPSRegister_S6, MIPSRegister_S7,
    MIPSRegister_T8, MIPSRegister_T9,
    MIPSRegister_K0, MIPSRegister_K1,
    MIPSRegister_GP, MIPSRegister_SP, MIPSRegister_FP, MIPSRegister_RA,

    MIPSRegister_Count
};

enum MIPSCOP0Registers {
    MIPSRegisterCOP0_Index, MIPSRegisterCOP0_Random,
    MIPSRegisterCOP0_EntryLo0, MIPSRegisterCOP0_EntryLo1,
    MIPSRegisterCOP0_Context, MIPSRegisterCOP0_PageMask,
    MIPSRegisterCOP0_Wired, MIPSRegisterCOP0_Reserved,
    MIPSRegisterCOP0_BadVAddr, MIPSRegisterCOP0_Count,
    MIPSRegisterCOP0_EntryHi, MIPSRegisterCOP0_Compare,
    MIPSRegisterCOP0_Status, MIPSRegisterCOP0_Cause,
    MIPSRegisterCOP0_EPC, MIPSRegisterCOP0_PRId,
    MIPSRegisterCOP0_Config, MIPSRegisterCOP0_LLAddr,
    MIPSRegisterCOP0_WatchLo, MIPSRegisterCOP0_WatchHi,
    MIPSRegisterCOP0_XContext,

    MIPSRegisterCOP0_CacheErr = 27,
    MIPSRegisterCOP0_TagLo, MIPSRegisterCOP0_TagHi,
    MIPSRegisterCOP0_ErrorEPC,

    MIPSRegisterCOP0_Count_ = 32
};

const std::array<const char*, MIPSRegister_Count> GPR_REGISTERS = {
    "$zero", "$at",
    "$v0", "$v1",
    "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9",
    "$k0", "$k1",
    "$gp", "$sp", "$fp", "$ra"
};

const std::array<const char*, MIPSRegisterCOP0_Count_> COP0_REGISTERS = {
    "$Index", "$Random", "$EntryLo0", "$EntryLo1",
    "$Context", "$PageMask", "$Wired", "$Reserved",
    "$BadVAddr", "$Count", "$EntryHi", "$Compare",
    "$Status", "$Cause", "$EPC", "PRId", "$Config",
    "$LLAddr", "$WatchLo", "$WatchHi", "$XContext",
    "$21", "$22", "$23", "$24", "$25", "$26",
    "$CacheErr", "$TagLo", "$TagHi", "$ErrorEPC",
    "$31"
};
