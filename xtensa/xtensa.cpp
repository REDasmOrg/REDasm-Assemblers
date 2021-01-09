#include "xtensa.h"
#include "xtensa_registers.h"

template<size_t endianness>
const XtensaInstruction* XtensaDecoder<endianness>::decode(const RDBufferView* view)
{
    XTensaOpcodeBytes xbytes{ };
    if(!XtensaDecoder<endianness>::fetch(view, &xbytes)) return nullptr;
    return XtensaDecoder<endianness>::findInstruction(&xbytes);

    // switch(def->encoding)
    // {
    //     case XtensaEncoding_None:
    //     case XtensaEncoding_NNone:
    //         break;

    //     case XtensaEncoding_RRR:         XtensaDecoder<endianness>::formatRRR(instruction, &xbytes);         break;
    //     case XtensaEncoding_RRR_2r:      XtensaDecoder<endianness>::formatRRR_2r(instruction, &xbytes);      break;
    //     case XtensaEncoding_RRR_2rr:     XtensaDecoder<endianness>::formatRRR_2rr(instruction, &xbytes);     break;
    //     case XtensaEncoding_RRR_2imm:    XtensaDecoder<endianness>::formatRRR_2imm(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRR_extui:   XtensaDecoder<endianness>::formatRRR_extui(instruction, &xbytes);   break;
    //     case XtensaEncoding_RRR_1imm:    XtensaDecoder<endianness>::formatRRR_1imm(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRR_immr:    XtensaDecoder<endianness>::formatRRR_immr(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRR_sext:    XtensaDecoder<endianness>::formatRRR_sext(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRR_sll:     XtensaDecoder<endianness>::formatRRR_sll(instruction, &xbytes);     break;
    //     case XtensaEncoding_RRR_slli:    XtensaDecoder<endianness>::formatRRR_slli(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRR_srai:    XtensaDecoder<endianness>::formatRRR_srai(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRR_sh:      XtensaDecoder<endianness>::formatRRR_sh(instruction, &xbytes);      break;
    //     case XtensaEncoding_RRR_ssa:     XtensaDecoder<endianness>::formatRRR_ssa(instruction, &xbytes);     break;
    //     case XtensaEncoding_RRR_ssai:    XtensaDecoder<endianness>::formatRRR_ssai(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRI8:        XtensaDecoder<endianness>::formatRRI8(instruction, &xbytes);        break;
    //     case XtensaEncoding_RRI8_addmi:  XtensaDecoder<endianness>::formatRRI8_addmi(instruction, &xbytes);  break;
    //     case XtensaEncoding_RRI8_b:      XtensaDecoder<endianness>::formatRRI8_b(instruction, &xbytes);      break;
    //     case XtensaEncoding_RRI8_bb:     XtensaDecoder<endianness>::formatRRI8_bb(instruction, &xbytes);     break;
    //     case XtensaEncoding_RRI8_i12:    XtensaDecoder<endianness>::formatRRI8_i12(instruction, &xbytes);    break;
    //     case XtensaEncoding_RRI8_disp:   XtensaDecoder<endianness>::formatRRI8_disp(instruction, &xbytes);   break;
    //     case XtensaEncoding_RRI8_disp16: XtensaDecoder<endianness>::formatRRI8_disp16(instruction, &xbytes); break;
    //     case XtensaEncoding_RRI8_disp32: XtensaDecoder<endianness>::formatRRI8_disp32(instruction, &xbytes); break;
    //     case XtensaEncoding_RI16:        XtensaDecoder<endianness>::formatRI16(instruction, &xbytes);        break;
    //     case XtensaEncoding_RSR:         XtensaDecoder<endianness>::formatRSR(instruction, &xbytes);         break;
    //     case XtensaEncoding_RSR_spec:    XtensaDecoder<endianness>::formatRSR_spec(instruction, &xbytes);    break;
    //     case XtensaEncoding_CALL:        XtensaDecoder<endianness>::formatCALL(instruction, &xbytes);        break;
    //     case XtensaEncoding_CALL_sh:     XtensaDecoder<endianness>::formatCALL_sh(instruction, &xbytes);     break;
    //     case XtensaEncoding_CALLX:       XtensaDecoder<endianness>::formatCALLX(instruction, &xbytes);       break;
    //     case XtensaEncoding_BRI8_imm:    XtensaDecoder<endianness>::formatBRI8_imm(instruction, &xbytes);    break;
    //     case XtensaEncoding_BRI8_immu:   XtensaDecoder<endianness>::formatBRI8_immu(instruction, &xbytes);   break;
    //     case XtensaEncoding_BRI12:       XtensaDecoder<endianness>::formatBRI12(instruction, &xbytes);       break;
    //     case XtensaEncoding_RRRN:        XtensaDecoder<endianness>::formatRRRN(instruction, &xbytes);        break;
    //     case XtensaEncoding_RRRN_disp:   XtensaDecoder<endianness>::formatRRRN_disp(instruction, &xbytes);   break;
    //     case XtensaEncoding_RRRN_addi:   XtensaDecoder<endianness>::formatRRRN_addi(instruction, &xbytes);   break;
    //     case XtensaEncoding_RRRN_2r:     XtensaDecoder<endianness>::formatRRRN_2r(instruction, &xbytes);     break;
    //     case XtensaEncoding_RI7:         XtensaDecoder<endianness>::formatRI7(instruction, &xbytes);         break;
    //     case XtensaEncoding_RI6:         XtensaDecoder<endianness>::formatRI6(instruction, &xbytes);         break;
    //     case XtensaEncoding_RI12S3:      XtensaDecoder<endianness>::formatRI12S3(instruction, &xbytes);      break;
    //     default: rd_problem("Invalid format: " + std::to_string(def->encoding));                             break;
    // }
}

template<size_t endianness>
void XtensaDecoder<endianness>::emulate(const RDAssemblerPlugin*, RDEmulateResult* result)
{
    const RDBufferView* view = RDEmulateResult_GetView(result);
    const XtensaInstruction* xinstr = XtensaDecoder<endianness>::decode(view);

    switch(xinstr->encoding)
    {
        case XtensaEncoding_CALL:
        case XtensaEncoding_CALL_sh:
            RDDisassembler_EnqueueAddress(disassembler, instruction->operands[0].address, instruction);
            break;

        case XtensaEncoding_RI16:
        case XtensaEncoding_BRI12:
            RDDisassembler_EnqueueAddress(disassembler, instruction->operands[1].address, instruction);
            break;

        case XtensaEncoding_RRI8_b:
        case XtensaEncoding_RRI8_bb:
        case XtensaEncoding_BRI8_imm:
        case XtensaEncoding_BRI8_immu:
            RDDisassembler_EnqueueAddress(disassembler, instruction->operands[2].address, instruction);
            break;

        default: break;
    }

    if(IS_TYPE(instruction, InstructionType_Jump) && !HAS_FLAG(instruction, InstructionFlags_Conditional)) return;
    if(HAS_FLAG(instruction, InstructionFlags_Stop)) return;

    RDDisassembler_Next(disassembler, instruction);
}

template<size_t endianness>
bool XtensaDecoder<endianness>::render(const RDAssemblerPlugin*, RDRenderItemParams* rip)
{
    if(!IS_TYPE(rip, RendererItemType_Operand)) return false;
    if(!IS_TYPE(rip->operand, OperandType_Register)) return false;

    if(rip->operand->u_data)
    {
        auto it = Xtensa_SpecialRegisters.find(rip->operand->reg);

        if(it != Xtensa_SpecialRegisters.end())
            RDRendererItem_Push(rip->rendereritem, it->second, "register_fg", nullptr);
        else
            RDRendererItem_Push(rip->rendereritem, "???", "register_fg", nullptr);
    }
    else
        RDRendererItem_Push(rip->rendereritem, ("a" + std::to_string(rip->operand->reg)).c_str(), "register_fg", nullptr);

    return true;
}

template<size_t endianness>
const XtensaInstruction *XtensaDecoder<endianness>::findInstruction(const XTensaOpcodeBytes *xbytes)
{
    for(size_t i = 0; i < Xtensa_DefinitionsCount; i++)
    {
        const XtensaInstruction* def = &Xtensa_Definitions[i];

        if((xbytes->opcode & def->mask) == def->opcode)
            return def;
    }

    return nullptr;
}

template<size_t endianness>
bool XtensaDecoder<endianness>::fetch(const RDBufferView* view, XTensaOpcodeBytes *xbytes)
{
    if(view->size < 3) return false;
    u8* data = view->data;

    if constexpr(endianness == Endianness_Little)
    {
        xbytes->b1 = *data;
        xbytes->b2 = *(data + 1);
        xbytes->b3 = *(data + 2);
    }
    else
    {
        xbytes->b3 = *data;
        xbytes->b2 = *(data + 1);
        xbytes->b1 = *(data + 2);
    }

    return true;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_2r(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_2rr(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_2imm(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = t;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_extui(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 op2 = (xbytes->opcode & 0xF00000) >> 20;
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u8 sa4 = (xbytes->opcode & 0x10000) >> 16;
    u8 sa3_0 = (xbytes->opcode & 0xF00) >> 8;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = (sa4 << 4) | sa3_0;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = op2 + 1;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_1imm(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm4 = (xbytes->opcode & 0xF00) >> 8;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = imm4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_immr(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm4 = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = imm4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_sext(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    rd_log("Operands missing @ " + rd_tohex(instruction->address));
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_sll(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_slli(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 sa4 = (xbytes->opcode & 0x100000) >> 20;
    u8 sa3_0 = (xbytes->opcode & 0xF0) >> 4;
    u8 sa = (sa4 << 4) | sa3_0;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = sa;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_srai(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 sa4 = (xbytes->opcode & 0x100000) >> 20;
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 sa3_0 = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u8 sa = (sa4 << 4) | sa3_0;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = sa;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_sh(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u8 sa = (xbytes->opcode & 0xF00) >> 8;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = sa;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_ssa(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRR_ssai(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 sa3_0 = (xbytes->opcode & 0xF00) >> 8;
    u8 sa4 = (xbytes->opcode & 0x10) >> 4;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = (sa4 << 4) | sa3_0;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = imm8;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8_addmi(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = imm8 << 8;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8_b(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->address = instruction->address + imm8 + 4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8_bb(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->address = instruction->address + imm8 + 4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8_i12(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u16 imm12__7_0 = (xbytes->opcode & 0xFF0000) >> 16;
    u16 imm12__11_8 = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = RD_SignExt((imm12__11_8 << 8) | imm12__7_0, 12);
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8_disp(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->reg = imm8 * 2;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8_disp16(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u16 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->reg = imm8 * 2;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRI8_disp32(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;

    auto* op = RDInstruction_PushOperand(instruction, OperandType_Displacement);
    op->base = s;
    op->displacement = imm8 << 2;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRI16(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u16 imm16 = (xbytes->opcode & 0xFFFF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u32 dest = (0xFFFF0000 | imm16) << 2;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Memory)->u_value = dest + static_cast<u32>(((instruction->address + 3) & 0xFFFFFFFC));
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRSR(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 sr = (xbytes->opcode & 0xFF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;

    auto* op = RDInstruction_PushOperand(instruction, OperandType_Register);
    op->reg = sr;
    op->u_data = 1;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRSR_spec(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatCALL(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s32 target = static_cast<s32>(RD_SignExt((xbytes->opcode & 0xFFFFFFC0) >> 6, 18));
    target += instruction->address + 4;

    RDInstruction_PushOperand(instruction, OperandType_Immediate)->address = target;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatCALL_sh(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s32 target = static_cast<s32>(RD_SignExt((xbytes->opcode & 0xFFFFC0) >> 6, 18));
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->address = (instruction->address & 0xFFFFFFFC) + (target << 2) + 4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatCALLX(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatBRI8_imm(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s8 imm8 = RD_SignExt((xbytes->opcode & 0xFF0000) >> 16, 8);
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = r;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = instruction->address + imm8 + 4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatBRI8_immu(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s8 imm8 = RD_SignExt((xbytes->opcode & 0xFF0000) >> 16, 8);
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = r;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = instruction->address + imm8 + 4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatBRI12(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    s16 imm12 = RD_SignExt((xbytes->opcode & 0xFFF000) >> 12, 12);
    u8 s = (xbytes->opcode & 0xF00) >> 8;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->u_value = instruction->address + imm12 + 4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRRN(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRRN_disp(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm4 = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->reg = imm4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRRN_addi(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = r;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRRRN_2r(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = t;
    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRI7(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm7__3_0 = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 imm7__6_4 = (xbytes->opcode & 0x70) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = (imm7__6_4 << 4) | imm7__3_0;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRI6(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u8 imm6__3_0 = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 imm6__5_4 = (xbytes->opcode & 0x30) >> 4;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Immediate)->reg = instruction->address + (static_cast<s8>((imm6__5_4 << 4) | imm6__3_0)) + 4;
}

template<size_t endianness>
void XtensaDecoder<endianness>::formatRI12S3(RDInstruction *instruction, const XTensaOpcodeBytes *xbytes)
{
    u16 imm12 = (xbytes->opcode & 0xFFF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;

    RDInstruction_PushOperand(instruction, OperandType_Register)->reg = s;
    RDInstruction_PushOperand(instruction, OperandType_Constant)->u_value = imm12 * 8;
}

void redasm_entry()
{
    RD_PLUGIN_CREATE(RDAssemblerPlugin, xtensale, "Xtensa (Little Endian)");
    xtensale.bits = 32;
    xtensale.decode = &XtensaDecoder<Endianness_Little>::decode;
    xtensale.emulate = &XtensaDecoder<Endianness_Little>::emulate;
    xtensale.render = &XtensaDecoder<Endianness_Little>::render;
    RDAssembler_Register(&xtensale);

    RD_PLUGIN_CREATE(RDAssemblerPlugin, xtensabe, "Xtensa (Big Endian)");
    xtensabe.bits = 32;
    xtensabe.decode = &XtensaDecoder<Endianness_Big>::decode;
    xtensabe.emulate = &XtensaDecoder<Endianness_Big>::emulate;
    xtensabe.render = &XtensaDecoder<Endianness_Big>::render;
    RDAssembler_Register(&xtensabe);
}

template class XtensaDecoder<Endianness_Little>;
template class XtensaDecoder<Endianness_Big>;
