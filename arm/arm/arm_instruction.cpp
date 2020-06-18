#include "arm_instruction.h"

std::unordered_map<u32, ARMOpcode> ARMOp_DataProcessing;
std::unordered_map<u32, ARMOpcode> ARMOp_HalfWordRegister;
std::unordered_map<u32, ARMOpcode> ARMOp_SingleDataTransfer;
std::unordered_map<u32, ARMOpcode> ARMOp_Undefined;
std::unordered_map<u32, ARMOpcode> ARMOp_BlockDataTransfer;
std::unordered_map<u32, ARMOpcode> ARMOp_Branch;

void InitializeARM()
{
    ARMOp_DataProcessing[0x00000000] = { "and", ARMInstruction_And, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02000000] = { "and", ARMInstruction_And, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x00200000] = { "eor", ARMInstruction_Eor, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02200000] = { "eor", ARMInstruction_Eor, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x00400000] = { "sub", ARMInstruction_Sub, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02400000] = { "sub", ARMInstruction_Sub, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x00600000] = { "rsb", ARMInstruction_Rsb, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02600000] = { "rsb", ARMInstruction_Rsb, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x00800000] = { "add", ARMInstruction_Add, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02800000] = { "add", ARMInstruction_Add, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x00A00000] = { "adc", ARMInstruction_Adc, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02A00000] = { "adc", ARMInstruction_Adc, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x00C00000] = { "sbc", ARMInstruction_Sbc, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02C00000] = { "sbc", ARMInstruction_Sbc, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x00E00000] = { "rsc", ARMInstruction_Rsc, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x02E00000] = { "rsc", ARMInstruction_Rsc, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01000000] = { "tst", ARMInstruction_Tst, { ARMOperand_Rn, ARMOperand_2Register, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03000000] = { "tst", ARMInstruction_Tst, { ARMOperand_Rn, ARMOperand_2Immediate, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01200000] = { "teq", ARMInstruction_Teq, { ARMOperand_Rn, ARMOperand_2Register, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03200000] = { "teq", ARMInstruction_Teq, { ARMOperand_Rn, ARMOperand_2Immediate, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01400000] = { "cmp", ARMInstruction_Cmp, { ARMOperand_Rn, ARMOperand_2Register, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03400000] = { "cmp", ARMInstruction_Cmp, { ARMOperand_Rn, ARMOperand_2Immediate, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01600000] = { "cmn", ARMInstruction_Cmn, { ARMOperand_Rn, ARMOperand_2Register, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03600000] = { "cmn", ARMInstruction_Cmn, { ARMOperand_Rn, ARMOperand_2Immediate, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01800000] = { "orr", ARMInstruction_Orr, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03800000] = { "orr", ARMInstruction_Orr, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01A00000] = { "mov", ARMInstruction_Mov, { ARMOperand_Rd, ARMOperand_2Register, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03A00000] = { "mov", ARMInstruction_Mov, { ARMOperand_Rd, ARMOperand_2Immediate, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01C00000] = { "bic", ARMInstruction_Bic, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Register, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03C00000] = { "bic", ARMInstruction_Bic, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_2Immediate, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x01E00000] = { "mvn", ARMInstruction_Mvn, { ARMOperand_Rd, ARMOperand_2Register, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };
    ARMOp_DataProcessing[0x03E00000] = { "mvn", ARMInstruction_Mvn, { ARMOperand_Rd, ARMOperand_2Immediate, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_DataProcessing };

    ARMOp_HalfWordRegister[0x00100090] = { "ldr", ARMInstruction_Ldr, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_Rm, 0, 0}, InstructionType_Load, InstructionFlags_None, ARMFormat_HalfWordRegister };
    ARMOp_HalfWordRegister[0x00000090] = { "str", ARMInstruction_Str, { ARMOperand_Rd, ARMOperand_Rn, ARMOperand_Rm, 0, 0}, InstructionType_Load, InstructionFlags_None, ARMFormat_HalfWordRegister };

    ARMOp_SingleDataTransfer[0x04000000] = { "str", ARMInstruction_Str, { ARMOperand_Rd, ARMOperand_Offset12, 0, 0, 0 }, InstructionType_Store, InstructionFlags_None, ARMFormat_SingleDataTransfer};
    ARMOp_SingleDataTransfer[0x04100000] = { "ldr", ARMInstruction_Ldr, { ARMOperand_Rd, ARMOperand_Offset12, 0, 0, 0 }, InstructionType_Load, InstructionFlags_None, ARMFormat_SingleDataTransfer};

    ARMOp_Undefined[0x06000010] = { "undefined", ARMInstruction_Undefined, { 0, 0, 0, 0, 0 }, InstructionType_None, InstructionFlags_None, ARMFormat_Undefined };

    ARMOp_BlockDataTransfer[0x08000000] = { "stm", ARMInstruction_Stm, { ARMOperand_Rn, ARMOperand_RegList, 0, 0, 0 }, InstructionType_Store, InstructionFlags_None, ARMFormat_BlockDataTransfer };
    ARMOp_BlockDataTransfer[0x08100000] = { "ldm", ARMInstruction_Ldm, { ARMOperand_Rn, ARMOperand_RegList, 0, 0, 0 }, InstructionType_Load, InstructionFlags_None, ARMFormat_BlockDataTransfer };

    ARMOp_Branch[0x0A000000] = { "b", ARMInstruction_B, { ARMOperand_Offset24, 0, 0, 0, 0 }, InstructionType_Jump, InstructionFlags_None, ARMFormat_Branch };
    ARMOp_Branch[0x0B000000] = { "bl", ARMInstruction_Bl, { ARMOperand_Offset24, 0, 0, 0, 0 }, InstructionType_Call, InstructionFlags_None, ARMFormat_Branch };
}
