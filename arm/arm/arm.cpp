#include "arm.h"
#include "arm_conditions.h"
#include "arm_registers.h"

#define ARM_IS_CONDITIONAL(cond) (cond != 0b1110)

#define ARM_DATA_PROCESSING_MASK      0x0FE00000
#define ARM_SINGLE_DATA_TRANSFER_MASK 0x0C100000
#define ARM_BLOCK_DATA_TRANSFER_MASK  0x0E100000
#define ARM_BRANCH_MASK               0x0F000000

//#define ARM_DATA_UNDEFINED_MASK  0x0FE00000

const char* ARMDecoder::regname(RDAssemblerPlugin*, const RDInstruction*, rd_register_id r)
{
    if(r < ArmRegisters.size()) return ArmRegisters[r];
    return nullptr;
}

void ARMDecoder::emulate(const RDAssemblerPlugin*, RDDisassembler* disassembler, const RDInstruction* instruction)
{
    switch(instruction->id)
    {
        case ARMInstruction_B:
        case ARMInstruction_Bl:
            RDDisassembler_EnqueueAddress(disassembler, instruction, instruction->operands[0].address);
            break;

        default:
            RDDisassembler_CheckOperands(disassembler, instruction);
            break;
    }

    if(HAS_FLAG(instruction, InstructionFlags_Stop) || (IS_TYPE(instruction, InstructionType_Jump) && !HAS_FLAG(instruction, InstructionFlags_Conditional)))
        return;

    RDDisassembler_EnqueueNext(disassembler, instruction);
}

bool ARMDecoder::render(const RDAssemblerPlugin*, RDRenderItemParams* rip)
{
    if(!IS_TYPE(rip, RendererItemType_Instruction)) return false;

    RDRenderer_Prologue(rip);
    RDRenderer_Mnemonic(rip);

    for(size_t i = 0; i < rip->instruction->operandscount; i++)
    {
        if(i) RDRenderer_Text(rip, ", ");

        const RDOperand& op = rip->instruction->operands[i];
        if(op.u_data & ARMFlags_ListBegin) RDRenderer_Text(rip, "{");
        else if(op.u_data & ARMFlags_DispBegin) RDRenderer_Text(rip, "[");

        if(IS_TYPE(&op, OperandType_Immediate))
        {
            switch(rip->instruction->id)
            {
                case ARMInstruction_B:
                case ARMInstruction_Bl:
                    break;

                default: RDRenderer_Text(rip, "#"); break;
            }

            RDRenderer_Operand(rip, &op);
        }
        else if(IS_TYPE(&op, OperandType_Displacement))
        {
            RDRenderer_Text(rip, "[");
            RDRenderer_Register(rip, op.reg1);

            if(op.reg2 != RD_NPOS)
            {
                RDRenderer_Text(rip, ",");
                RDRenderer_Register(rip, op.reg2);
            }

            if(op.displacement)
            {
                RDRenderer_Text(rip, ", ");
                if(op.displacement < 0) RDRenderer_Text(rip, "-");
                RDRenderer_Immediate(rip, std::abs(op.displacement));
            }

            RDRenderer_Text(rip, "]");
        }
        else if(IS_TYPE(&op, ARMOperand_2Register))
        {
            RDRenderer_Register(rip, op.reg1);

            if(op.reg2 != RD_NPOS)
            {
                RDRenderer_Text(rip, ",");
                RDRenderer_Register(rip, op.reg2);
            }

            ARMDecoder::renderShift(rip, &op);
        }
        else if(IS_TYPE(&op, ARMOperand_Offset12))
        {
            RDRenderer_Text(rip, "[");
            RDRenderer_Register(rip, op.base);

            if(op.reg3 != RD_NPOS)
            {
                RDRenderer_Text(rip, ",");
                RDRenderer_Register(rip, op.reg3);
            }

            ARMDecoder::renderShift(rip, &op);
            RDRenderer_Text(rip, "]");
        }
        else
            RDRenderer_Operand(rip, &op);

        if(op.u_data & ARMFlags_WriteBack) RDRenderer_Text(rip, "!");

        if(op.u_data & ARMFlags_ListEnd) RDRenderer_Text(rip, "}");
        else if(op.u_data & ARMFlags_ListEnd) RDRenderer_Text(rip, "]");
    }

    return true;
}

size_t ARMDecoder::classify(const ARMInstruction* ai)
{
    if(ai->swinterrupt.fixed == 0b1111) return ARMFormat_SwInterrupt;
    if(ai->copdatatransfer.fixed == 0b110) return ARMFormat_CopDataTransfer;
    if(ai->branch.fixed == 0b101) return ARMFormat_Branch;
    if(ai->blockdatatransfer.fixed == 0b100) return ARMFormat_BlockDataTransfer;

    if(ai->copdataoperation.fixed == 0b1110)
    {
        if(ai->copdataoperation.b1) return ARMFormat_CopRegTransfer;
        return ARMFormat_CopDataTransfer;
    }

    if(ai->singledatatransfer.fixed == 0b01)
    {
        if((ai->undefined.fixed == 0b011) && ai->undefined.b1)
            return ARMFormat_Undefined;

        return ARMFormat_SingleDataTransfer;
    }

    if(ai->hwordregister.fixed == 0b000)
    {
        if(ai->hwordimmediate.b3 && ai->hwordimmediate.b2 && ai->hwordimmediate.b1)
            return ARMFormat_HalfWordImmediate;

        if(!ai->hwordregister.b4 && !ai->hwordregister.b3 && ai->hwordregister.b2 && ai->hwordregister.b1)
            return ARMFormat_HalfWordRegister;
    }

    if(ai->singledataswap.fixed == 0b00010)
    {
        if(ai->branchexchange.fixed == 0b000100101111111111110001)
            return ARMFormat_BranchExchange;

        if(!ai->singledataswap.b2 && (ai->singledataswap.b1 == 0b00001001))
            return ARMFormat_SingleDataSwap;
    }

    if((ai->multiplylong.fixed == 0b00001) && (ai->multiplylong.b1 == 0b1001))
        return ARMFormat_MultiplyLong;

    if(!ai->multiply.fixed && (ai->multiply.b1 == 0b1001)) return ARMFormat_Multiply;
    if(!ai->dataprocessing.fixed) return ARMFormat_DataProcessing;

    return ARMFormat_None;
}

void ARMDecoder::renderShift(RDRenderItemParams* rip, const RDOperand* op)
{
    static std::unordered_map<rd_type, const char*> shiftids = {
        { ARMFlags_LSL, "LSL" },
        { ARMFlags_LSR, "LSR" },
        { ARMFlags_ASR, "ASR" },
        { ARMFlags_RRX, "RRX" },
    };

    if(!op->u_value) return;
    RDRenderer_Text(rip, ",");

    if(auto it = shiftids.find(op->u_data); it != shiftids.end())
    {
        RDRenderer_Text(rip, shiftids[op->u_data]);
        RDRenderer_Text(rip, "#");
        RDRenderer_Immediate(rip, op->u_value);
    }
    else
        RDRenderer_Text(rip, "InvalidShift");
}

void ARMDecoder::checkShift(RDOperand* op, u8 shift)
{
    static std::array<rd_flag, 0b100> shifttypes = {
        ARMFlags_LSL, ARMFlags_LSR, ARMFlags_ASR, ARMFlags_RRX
    };

    rd_flag shifttype = shifttypes[(shift & 0b110) >> 1];

    if(shift & 0b1)
    {
        u8 shiftreg = (shift & 0b11110000) >> 4;
        op->u_data = shifttype;
        op->reg2 = shiftreg; // rs
    }
    else
    {
        u8 shiftamt = (shift & 0b11111000) >> 3;
        if(!shiftamt) return;

        op->u_data = shifttype;
        op->u_value = shiftamt;
    }
}

void ARMDecoder::checkStop(RDInstruction* instruction)
{
    switch(instruction->id)
    {
        case ARMInstruction_Ldm:
            for(size_t i = 1; i < instruction->operandscount; i++) {
                if(instruction->operands[i].reg == ARMRegister_PC) {
                    instruction->flags |= InstructionFlags_Stop;
                    return;
                }
            }
            break;

        case ARMInstruction_Mov:
        case ARMInstruction_Ldr:
            if(instruction->operands[0].reg == ARMRegister_PC)
                instruction->flags |= InstructionFlags_Stop;
            break;

        default: break;
    }
}

void ARMDecoder::compile(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    instruction->id = armop->id;
    instruction->type = armop->type;
    instruction->flags = armop->flags;

    for(size_t opdef : armop->operands)
    {
        switch(opdef)
        {
            case ARMOperand_None: break;
            case ARMOperand_RegList: ARMDecoder::compileRegList(instruction, ai, armop); break;

            case ARMOperand_2Register: ARMDecoder::compile2Register(instruction, ai, armop); break;
            case ARMOperand_2Immediate: ARMDecoder::compile2Immediate(instruction, ai, armop); break;

            case ARMOperand_Offset4: ARMDecoder::compileOffset4(instruction, ai, armop); break;
            case ARMOperand_Offset12: ARMDecoder::compileOffset12(instruction, ai, armop); break;
            case ARMOperand_Offset24: ARMDecoder::compileOffset24(instruction, ai, armop); break;

            case ARMOperand_Rn: ARMDecoder::compileRn(instruction, ai, armop); break;
            case ARMOperand_Rd: ARMDecoder::compileRd(instruction, ai, armop); break;
            case ARMOperand_Rm: ARMDecoder::compileRm(instruction, ai, armop); break;

            case ARMOperand_RdHi: break;
            case ARMOperand_RdLo: break;

            case ARMOperand_CRn: break;
            case ARMOperand_CRm: break;

            case ARMOperand_CRd: break;
            case ARMOperand_CPn: break;
            case ARMOperand_CP: break;

            default:
                rd_log("Unhandled operand definition: " + std::to_string(opdef));
                break;
        }
    }
}

bool ARMDecoder::decodeDataProcessing(RDInstruction* instruction, const ARMInstruction* ai)
{
    auto it = ARMOp_DataProcessing.find(ai->word & ARM_DATA_PROCESSING_MASK);
    if(it == ARMOp_DataProcessing.end()) return false;

    ARMDecoder::compile(instruction, ai, &it->second);

    std::string m = GetArmMnemonic(&it->second, ai->dataprocessing.cond);
    RDInstruction_SetMnemonic(instruction, m.c_str());
    return true;
}

bool ARMDecoder::decodeMultiply(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeMultiplyLong(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeSingleDataSwap(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeBranchAndExchange(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeHalfWordRegister(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeHalfWordImmediate(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeSingleDataTransfer(RDInstruction* instruction, const ARMInstruction* ai)
{
    auto it = ARMOp_SingleDataTransfer.find(ai->word & ARM_SINGLE_DATA_TRANSFER_MASK);
    if(it == ARMOp_SingleDataTransfer.end()) return false;

    ARMDecoder::compile(instruction, ai, &it->second);
    std::string m = GetArmMnemonic(&it->second, ai->singledatatransfer.cond);
    if(ai->singledatatransfer.b) m += "b";

    RDInstruction_SetMnemonic(instruction, m.c_str());
    return true;
}

bool ARMDecoder::decodeBlockDataTransfer(RDInstruction* instruction, const ARMInstruction* ai)
{
    auto it = ARMOp_BlockDataTransfer.find(ai->word & ARM_BLOCK_DATA_TRANSFER_MASK);
    if(it == ARMOp_BlockDataTransfer.end()) return false;

    ARMDecoder::compile(instruction, ai, &it->second);

    std::string m = GetArmMnemonic(&it->second, ai->blockdatatransfer.cond);
    const auto& bdt = ai->blockdatatransfer;

    if(bdt.w) instruction->operands[0].u_data |= ARMFlags_WriteBack;

    u8 lpu = (bdt.l << 2) | (bdt.p << 1) | bdt.u;
    bool issp = bdt.rn == ARMRegister_SP;

    if(instruction->id == ARMInstruction_Ldm)
    {
        switch(lpu)
        {
            case 0b111: m += issp ? "ed" : "ib"; break;
            case 0b101: m += issp ? "fd" : "ia"; break;
            case 0b110: m += issp ? "ea" : "db"; break;
            case 0b100: m += issp ? "fa" : "da"; break;
            default: rd_log("Unhandled Load lpu: " + rd_tohex(lpu)); break;
        }
    }
    else
    {
        switch(lpu)
        {
            case 0b011: m += issp ? "fa" : "ib"; break;
            case 0b001: m += issp ? "ea" : "ia"; break;
            case 0b010: m += issp ? "fd" : "db"; break;
            case 0b000: m += issp ? "ed" : "da"; break;
            default: rd_log("Unhandled Store lpu: " + rd_tohex(lpu)); break;
        }
    }

    RDInstruction_SetMnemonic(instruction, m.c_str());
    return true;
}

bool ARMDecoder::decodeBranch(RDInstruction* instruction, const ARMInstruction* ai)
{
    auto it = ARMOp_Branch.find(ai->word & ARM_BRANCH_MASK);
    if(it == ARMOp_Branch.end()) return false;

    ARMDecoder::compile(instruction, ai, &it->second);
    if(ARM_IS_CONDITIONAL(ai->branch.cond)) instruction->flags |= InstructionFlags_Conditional;

    std::string m = GetArmMnemonic(&it->second, ai->branch.cond);
    RDInstruction_SetMnemonic(instruction, m.c_str());
    return true;
}

bool ARMDecoder::decodeCopDataTransfer(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeCopOperator(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeCopRegTransfer(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

bool ARMDecoder::decodeSwInterrupt(RDInstruction* instruction, const ARMInstruction* ai)
{
    return false;
}

void ARMDecoder::compileRegList(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    if(armop->format != ARMFormat_BlockDataTransfer)
    {
        rd_log("Missing 'reglist' operand for format " + std::to_string(armop->format));
        return;
    }

    size_t c = instruction->operandscount;

    for(rd_register_id i = 0; i < ARMRegister_Count; i++)
    {
        u16 r = (1 << i);

        if(ai->blockdatatransfer.reglist & r)
            RDInstruction_PushOperand(instruction, OperandType_Register)->reg = i;
    }

    if(c >= instruction->operandscount) return;
    instruction->operands[c].u_data |= ARMFlags_ListBegin;
    RDInstruction_LastOperand(instruction)->u_data |= ARMFlags_ListEnd;
}

void ARMDecoder::compile2Register(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    if(armop->format != ARMFormat_DataProcessing)
    {
        rd_log("Missing '2operandreg' operand for format " + std::to_string(armop->format));
        return;
    }

    auto* op = RDInstruction_PushOperand(instruction, ARMOperand_2Register);
    op->reg1 = ai->dataprocessing.op2 & 0b1111; // rm
    ARMDecoder::checkShift(op, (ai->dataprocessing.op2 & 0b111111110000) >> 4);
}

void ARMDecoder::compile2Immediate(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    if(armop->format != ARMFormat_DataProcessing)
    {
        rd_log("Missing '2operandimm' operand for format " + std::to_string(armop->format));
        return;
    }

    auto* op = RDInstruction_PushOperand(instruction, OperandType_Immediate);
    u8 rotate = (ai->dataprocessing.op2 & 0b111100000000) >> 8;
    u8 imm = ai->dataprocessing.op2 & 0b11111111;
    op->u_value = RD_Ror32(imm, rotate);
}

void ARMDecoder::compileRn(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    switch(armop->format)
    {
        case ARMFormat_DataProcessing: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->dataprocessing.rn; break;
        case ARMFormat_Multiply: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->multiply.rn; break;
        case ARMFormat_MultiplyLong: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->multiplylong.rn; break;
        case ARMFormat_SingleDataSwap: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->singledataswap.rn; break;
        case ARMFormat_BranchExchange: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->branchexchange.rn; break;
        case ARMFormat_HalfWordRegister: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->hwordregister.rn; break;
        case ARMFormat_HalfWordImmediate: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->hwordimmediate.rn; break;
        case ARMFormat_SingleDataTransfer: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->singledatatransfer.rn; break;
        case ARMFormat_BlockDataTransfer: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->blockdatatransfer.rn; break;
        case ARMFormat_CopDataTransfer: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->copdatatransfer.rn; break;
        default: rd_log("Missing 'rn' operand for format " + std::to_string(armop->format)); break;
    }
}

void ARMDecoder::compileRd(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    switch(armop->format)
    {
        case ARMFormat_DataProcessing: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->dataprocessing.rd; break;
        case ARMFormat_Multiply: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->multiply.rd; break;
        case ARMFormat_SingleDataSwap: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->singledataswap.rd; break;
        case ARMFormat_HalfWordRegister: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->hwordregister.rd; break;
        case ARMFormat_HalfWordImmediate: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->hwordimmediate.rd; break;
        case ARMFormat_SingleDataTransfer: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->singledatatransfer.rd; break;
        case ARMFormat_CopRegTransfer: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->copregtransfer.rd; break;
        default: rd_log("Missing 'rd' operand for format " + std::to_string(armop->format)); break;
    }
}

void ARMDecoder::compileRm(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    switch(armop->format)
    {
        case ARMFormat_Multiply: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->multiply.rm; break;
        case ARMFormat_MultiplyLong: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->multiply.rm; break;
        case ARMFormat_SingleDataSwap: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->singledataswap.rm; break;
        case ARMFormat_HalfWordRegister: RDInstruction_PushOperand(instruction, OperandType_Register)->reg = ai->hwordregister.rm; break;
        default: rd_log("Missing 'rm' operand for format " + std::to_string(armop->format)); break;
    }
}

void ARMDecoder::compileOffset4(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{

}

void ARMDecoder::compileOffset12(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    if(armop->format != ARMFormat_SingleDataTransfer)
    {
        rd_log("Missing 'offset12' operand for format " + std::to_string(armop->format));
        return;
    }

    if(ai->singledatatransfer.i)
    {
        auto* op = RDInstruction_PushOperand(instruction, ARMOperand_Offset12);
        op->base = ai->singledatatransfer.rn;
        op->reg3 = ai->singledatatransfer.offset & 0b1111; // rm
        ARMDecoder::checkShift(op, (ai->singledatatransfer.offset & 0b111111110000) >> 4);
    }
    else if(ai->singledatatransfer.rn == ARMRegister_PC)
    {
        auto* op = RDInstruction_PushOperand(instruction, OperandType_Memory);
        op->address = instruction->address + 8;

        if(!ai->singledatatransfer.u) op->address -= ai->singledatatransfer.offset;
        else op->address += ai->singledatatransfer.offset;
    }
    else
    {
        auto* op = RDInstruction_PushOperand(instruction, OperandType_Displacement);
        op->base = ai->singledatatransfer.rn;

        if(!ai->singledatatransfer.u) op->displacement = -ai->singledatatransfer.offset;
        else op->displacement = ai->singledatatransfer.offset;
    }
}

void ARMDecoder::compileOffset24(RDInstruction* instruction, const ARMInstruction* ai, const ARMOpcode* armop)
{
    if(armop->format != ARMFormat_Branch)
    {
        rd_log("Missing 'offset24' operand for format " + std::to_string(armop->format));
        return;
    }

    auto* op = RDInstruction_PushOperand(instruction, OperandType_Immediate);
    op->u_value = instruction->address + 8 + RD_SignExt(ai->branch.offset << 2, 26);
}

template<u32 (*Swap)(u32)>
bool ARMDecoder::decode(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction)
{
    if(RDBufferView_Size(view) < sizeof(ARMInstruction)) return false;
    instruction->size = sizeof(ARMInstruction);

    u32 word = Swap(*reinterpret_cast<u32*>(RDBufferView_Data(view)));
    ARMInstruction* ai = reinterpret_cast<ARMInstruction*>(reinterpret_cast<u32*>(&word));
    bool res = false;

    switch(ARMDecoder::classify(ai))
    {
        case ARMFormat_DataProcessing: res = ARMDecoder::decodeDataProcessing(instruction, ai); break;
        case ARMFormat_Multiply: res = ARMDecoder::decodeMultiply(instruction, ai); break;
        case ARMFormat_MultiplyLong: res = ARMDecoder::decodeMultiplyLong(instruction, ai); break;
        case ARMFormat_SingleDataSwap: res = ARMDecoder::decodeSingleDataSwap(instruction, ai); break;
        case ARMFormat_BranchExchange: res = ARMDecoder::decodeBranchAndExchange(instruction, ai); break;
        case ARMFormat_HalfWordRegister: res = ARMDecoder::decodeHalfWordRegister(instruction, ai); break;
        case ARMFormat_HalfWordImmediate: res = ARMDecoder::decodeHalfWordImmediate(instruction, ai); break;
        case ARMFormat_SingleDataTransfer: res = ARMDecoder::decodeSingleDataTransfer(instruction, ai); break;
        case ARMFormat_BlockDataTransfer: res = ARMDecoder::decodeBlockDataTransfer(instruction, ai); break;
        case ARMFormat_Branch: res = ARMDecoder::decodeBranch(instruction, ai); break;
        case ARMFormat_CopDataTransfer: res = ARMDecoder::decodeCopDataTransfer(instruction, ai); break;
        case ARMFormat_CopOperation: res = ARMDecoder::decodeCopOperator(instruction, ai); break;
        case ARMFormat_CopRegTransfer: res = ARMDecoder::decodeCopRegTransfer(instruction, ai); break;
        case ARMFormat_SwInterrupt: res = ARMDecoder::decodeSwInterrupt(instruction, ai); break;
        default: return false;
    }

    if(res) ARMDecoder::checkStop(instruction);
    return res;
}

template bool ARMDecoder::decode<RD_FromLittleEndian32>(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction);
template bool ARMDecoder::decode<RD_FromBigEndian32>(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction);
