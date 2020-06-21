#pragma once

#include <rdapi/rdapi.h>
#include <unordered_map>
#include <array>
#include "../common.h"

#define ARM_MAX_OPERANDS 5

enum ARMOperands: rd_type {
    ARMOperand_None = 0,
    ARMOperand_RegList = OperandType_Custom,

    ARMOperand_2Register, ARMOperand_2Immediate,
    ARMOperand_Offset4, ARMOperand_Offset12, ARMOperand_Offset24,

    ARMOperand_Rn, ARMOperand_Rd, ARMOperand_Rm,
    ARMOperand_RdHi, ARMOperand_RdLo,

    ARMOperand_CRn, ARMOperand_CRm, ARMOperand_CRd,
    ARMOperand_CPn, ARMOperand_CP,
};

enum ARMLevel {
    ARMLevel_None,

    ARMLevel_v4, ARMLevel_v4T,
    ARMLevel_v5T, ARMLevel_v5TE, ARMLevel_v5TEJ,
    ARMLevel_v6, ARMLevel_v6K, ARMLevel_v6T2,
    ARMLevel_v7,
    ARMLevel_v8, ARMLevel_v8_1, ARMLevel_v8_2,
};

enum ARMInstructionId {
    ARMInstruction_Invalid,
    ARMInstruction_Undefined,

    ARMInstruction_And,
    ARMInstruction_Eor,
    ARMInstruction_Sub,
    ARMInstruction_Rsb,
    ARMInstruction_Add,
    ARMInstruction_Adc,
    ARMInstruction_Sbc,
    ARMInstruction_Rsc,
    ARMInstruction_Tst,
    ARMInstruction_Teq,
    ARMInstruction_Cmp,
    ARMInstruction_Cmn,
    ARMInstruction_Orr,
    ARMInstruction_Mov,
    ARMInstruction_Bic,
    ARMInstruction_Mvn,

    ARMInstruction_B,
    ARMInstruction_Bl,
    ARMInstruction_Bx,

    ARMInstruction_Ldm,
    ARMInstruction_Stm,

    ARMInstruction_Ldr,
    ARMInstruction_Str,

    ARMInstruction_Count,
};

enum ARMFormat {
    ARMFormat_None,

    ARMFormat_Undefined,
    ARMFormat_DataProcessing,
    ARMFormat_Multiply,
    ARMFormat_MultiplyLong,
    ARMFormat_SingleDataSwap,
    ARMFormat_BranchExchange,
    ARMFormat_HalfWordRegister,
    ARMFormat_HalfWordImmediate,
    ARMFormat_SingleDataTransfer,
    ARMFormat_BlockDataTransfer,
    ARMFormat_Branch,
    ARMFormat_CopDataTransfer,
    ARMFormat_CopOperation,
    ARMFormat_CopRegTransfer,
    ARMFormat_SwInterrupt,

    ARMFormat_Count,
};

struct ARMOpcode {
    const char* mnemonic;
    rd_instruction_id id;
    std::array<size_t, ARM_MAX_OPERANDS> operands;
    rd_type type;
    rd_flag flags;
    size_t format;
};

#pragma pack(push, 1)
struct ARMDataProcessing {
    unsigned op2: 12;
    unsigned rd: 4;
    unsigned rn: 4;
    unsigned s: 1;
    unsigned opcode: 4;
    unsigned i: 1;
    unsigned fixed: 2;
    unsigned cond: 4;
};

typedef ARMDataProcessing ARMPSRTransfer;

struct ARMMultiply {
    unsigned rm: 4;
    unsigned b1: 4;
    unsigned rs: 4;
    unsigned rn: 4;
    unsigned rd: 4;
    unsigned s: 1;
    unsigned a: 1;
    unsigned fixed: 6;
    unsigned cond: 4;
};

struct ARMMultiplyLong {
    unsigned rm: 4;
    unsigned b1: 4;
    unsigned rn: 4;
    unsigned rdlo: 4;
    unsigned rdhi: 4;
    unsigned s: 1;
    unsigned a: 1;
    unsigned u: 1;
    unsigned fixed: 5;
    unsigned cond: 4;
};

struct ARMSingleDataSwap {
    unsigned rm: 4;
    unsigned b1: 8;
    unsigned rd: 4;
    unsigned rn: 4;
    unsigned b2: 2;
    unsigned b: 1;
    unsigned fixed: 5;
    unsigned cond: 4;
};

struct ARMHalfWordRegister {
    unsigned rm: 4;
    unsigned b1: 1;
    unsigned h: 1;
    unsigned s: 1;
    unsigned b2: 1;
    unsigned b3: 4;
    unsigned rd: 4;
    unsigned rn: 4;
    unsigned l: 1;
    unsigned w: 1;
    unsigned b4: 1;
    unsigned u: 1;
    unsigned p: 1;
    unsigned fixed: 3;
    unsigned cond: 4;
};

struct ARMHalfWordImmediate {
    unsigned offset1: 4;
    unsigned b1: 1;
    unsigned h: 1;
    unsigned s: 1;
    unsigned b2: 1;
    unsigned offset2: 4;
    unsigned rd: 4;
    unsigned rn: 4;
    unsigned l: 1;
    unsigned w: 1;
    unsigned b3: 1;
    unsigned u: 1;
    unsigned p: 1;
    unsigned fixed: 3;
    unsigned cond: 4;
};

struct ARMBranchExchange {
    unsigned rn: 4;
    unsigned fixed: 24;
    unsigned cond: 4;
};

struct ARMSwInterrupt {
    unsigned ignored: 24;
    unsigned fixed: 4;
    unsigned cond: 4;
};

struct ARMSingleDataTransfer {
    unsigned offset: 12;
    unsigned rd: 4;
    unsigned rn: 4;
    unsigned l: 1;
    unsigned w: 1;
    unsigned b: 1;
    unsigned u: 1;
    unsigned p: 1;
    unsigned i: 1;
    unsigned fixed: 2;
    unsigned cond: 4;
};

struct ARMBlockDataTransfer {
    unsigned reglist: 16;
    unsigned rn: 4;
    unsigned l: 1;
    unsigned w: 1;
    unsigned s: 1;
    unsigned u: 1;
    unsigned p: 1;
    unsigned fixed: 3;
    unsigned cond: 4;
};

struct ARMBranch {
    unsigned offset: 24;
    unsigned l: 1;
    unsigned fixed: 3;
    unsigned cond: 4;
};

struct ARMCopDataTransfer {
    unsigned offset: 8;
    unsigned cpno: 4;
    unsigned crd: 4;
    unsigned rn: 4;
    unsigned l: 1;
    unsigned w: 1;
    unsigned n: 1;
    unsigned u: 1;
    unsigned p: 1;
    unsigned fixed: 3;
    unsigned cond: 4;
};

struct ARMCopDataOperation {
    unsigned crm: 4;
    unsigned b1: 1;
    unsigned cp: 3;
    unsigned cpno: 4;
    unsigned crd: 4;
    unsigned crn: 4;
    unsigned cpopc: 4;
    unsigned fixed: 4;
    unsigned cond: 4;
};

struct ARMCopRegTransfer {
    unsigned crm: 4;
    unsigned b1: 1;
    unsigned cp: 3;
    unsigned cpno: 4;
    unsigned rd: 4;
    unsigned crn: 4;
    unsigned l: 1;
    unsigned cpopc: 3;
    unsigned fixed: 4;
    unsigned cond: 4;
};

struct ARMUndefined {
    unsigned undefined1: 4;
    unsigned b1: 1;
    unsigned undefined2: 20;
    unsigned fixed: 3;
    unsigned cond: 4;
};

union ARMInstruction {
    u32 word;

    ARMDataProcessing dataprocessing;
    ARMPSRTransfer psrtransfer;
    ARMMultiply multiply;
    ARMMultiplyLong multiplylong;
    ARMSingleDataSwap singledataswap;
    ARMBranchExchange branchexchange;
    ARMHalfWordRegister hwordregister;
    ARMHalfWordImmediate hwordimmediate;
    ARMSingleDataTransfer singledatatransfer;
    ARMUndefined undefined;
    ARMBlockDataTransfer blockdatatransfer;
    ARMBranch branch;
    ARMCopDataTransfer copdatatransfer;
    ARMCopDataOperation copdataoperation;
    ARMCopRegTransfer copregtransfer;
    ARMSwInterrupt swinterrupt;
};
#pragma pack(pop)

static_assert(sizeof(u32) == sizeof(ARMInstruction));

extern std::unordered_map<u32, ARMOpcode> ARMOp_DataProcessing;
extern std::unordered_map<u32, ARMOpcode> ARMOp_HalfWordRegister;
extern std::unordered_map<u32, ARMOpcode> ARMOp_SingleDataTransfer;
extern std::unordered_map<u32, ARMOpcode> ARMOp_BranchExchange;
extern std::unordered_map<u32, ARMOpcode> ARMOp_Undefined;
extern std::unordered_map<u32, ARMOpcode> ARMOp_BlockDataTransfer;
extern std::unordered_map<u32, ARMOpcode> ARMOp_Branch;

void InitializeARM();
