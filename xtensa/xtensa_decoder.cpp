#include "xtensa_decoder.h"
#include <redasm/support/utils.h>

XtensaDecoder::XtensaDecoder(endianness_t endianness): m_endianness(endianness) { }

bool XtensaDecoder::decode(const BufferView &view, Instruction *instruction)
{
    XTensaOpcodeBytes xbytes = { 0 };

    if(!this->fetch(view, &xbytes))
        return false;

    const XtensaInstructionDefinition* def = this->findInstruction(&xbytes);

    if(!def)
    {
        instruction->size = 3;
        return false;
    }

    instruction->mnemonic = def->mnemonic;
    instruction->type = def->type;
    instruction->size = def->narrow ? 2 : 3;

    switch(def->format)
    {
        case XtensaOpcodeFormat::None:
        case XtensaOpcodeFormat::NNone:
            break;

        case XtensaOpcodeFormat::RRR:         this->formatRRR(instruction, &xbytes, def);         break;
        case XtensaOpcodeFormat::RRR_2r:      this->formatRRR_2r(instruction, &xbytes, def);      break;
        case XtensaOpcodeFormat::RRR_2rr:     this->formatRRR_2rr(instruction, &xbytes, def);     break;
        case XtensaOpcodeFormat::RRR_2imm:    this->formatRRR_2imm(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRR_extui:   this->formatRRR_extui(instruction, &xbytes, def);   break;
        case XtensaOpcodeFormat::RRR_1imm:    this->formatRRR_1imm(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRR_immr:    this->formatRRR_immr(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRR_sext:    this->formatRRR_sext(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRR_sll:     this->formatRRR_sll(instruction, &xbytes, def);     break;
        case XtensaOpcodeFormat::RRR_slli:    this->formatRRR_slli(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRR_srai:    this->formatRRR_srai(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRR_sh:      this->formatRRR_sh(instruction, &xbytes, def);      break;
        case XtensaOpcodeFormat::RRR_ssa:     this->formatRRR_ssa(instruction, &xbytes, def);     break;
        case XtensaOpcodeFormat::RRR_ssai:    this->formatRRR_ssai(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRI8:        this->formatRRI8(instruction, &xbytes, def);        break;
        case XtensaOpcodeFormat::RRI8_addmi:  this->formatRRI8_addmi(instruction, &xbytes, def);  break;
        case XtensaOpcodeFormat::RRI8_b:      this->formatRRI8_b(instruction, &xbytes, def);      break;
        case XtensaOpcodeFormat::RRI8_bb:     this->formatRRI8_bb(instruction, &xbytes, def);     break;
        case XtensaOpcodeFormat::RRI8_i12:    this->formatRRI8_i12(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::RRI8_disp:   this->formatRRI8_disp(instruction, &xbytes, def);   break;
        case XtensaOpcodeFormat::RRI8_disp16: this->formatRRI8_disp16(instruction, &xbytes, def); break;
        case XtensaOpcodeFormat::RRI8_disp32: this->formatRRI8_disp32(instruction, &xbytes, def); break;
        case XtensaOpcodeFormat::RI16:        this->formatRI16(instruction, &xbytes, def);        break;
        case XtensaOpcodeFormat::RSR:         this->formatRSR(instruction, &xbytes, def);         break;
        case XtensaOpcodeFormat::RSR_spec:    this->formatRSR_spec(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::CALL:        this->formatCALL(instruction, &xbytes, def);        break;
        case XtensaOpcodeFormat::CALL_sh:     this->formatCALL_sh(instruction, &xbytes, def);     break;
        case XtensaOpcodeFormat::CALLX:       this->formatCALLX(instruction, &xbytes, def);       break;
        case XtensaOpcodeFormat::BRI8_imm:    this->formatBRI8_imm(instruction, &xbytes, def);    break;
        case XtensaOpcodeFormat::BRI8_immu:   this->formatBRI8_immu(instruction, &xbytes, def);   break;
        case XtensaOpcodeFormat::BRI12:       this->formatBRI12(instruction, &xbytes, def);       break;
        case XtensaOpcodeFormat::RRRN:        this->formatRRRN(instruction, &xbytes, def);        break;
        case XtensaOpcodeFormat::RRRN_disp:   this->formatRRRN_disp(instruction, &xbytes, def);   break;
        case XtensaOpcodeFormat::RRRN_addi:   this->formatRRRN_addi(instruction, &xbytes, def);   break;
        case XtensaOpcodeFormat::RRRN_2r:     this->formatRRR_2r(instruction, &xbytes, def);      break;
        case XtensaOpcodeFormat::RI7:         this->formatRI7(instruction, &xbytes, def);         break;
        case XtensaOpcodeFormat::RI6:         this->formatRI6(instruction, &xbytes, def);         break;
        case XtensaOpcodeFormat::RI12S3:      this->formatRI12S3(instruction, &xbytes, def);      break;
        default: r_ctx->problem("Invalid format: " + String::number(def->format));                break;
    }

    return true;
}

const XtensaInstructionDefinition *XtensaDecoder::findInstruction(const XTensaOpcodeBytes *xbytes) const
{
    for(size_t i = 0; i < Xtensa::definitionsCount; i++)
    {
        const XtensaInstructionDefinition* def = &Xtensa::definitions[i];

        if((xbytes->opcode & def->mask) == def->opcode)
            return def;
    }

    return nullptr;
}

bool XtensaDecoder::fetch(const BufferView& view, XTensaOpcodeBytes *xbytes) const
{
    if(view.size() < 3)
        return false;

    if(m_endianness == Endianness::LittleEndian)
    {
        xbytes->b1 = *view.data();
        xbytes->b2 = *(view.data() + 1);
        xbytes->b3 = *(view.data() + 2);
    }
    else
    {
        xbytes->b3 = *view.data();
        xbytes->b2 = *(view.data() + 1);
        xbytes->b1 = *(view.data() + 2);
    }

    return true;
}

void XtensaDecoder::formatRRR(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(r)->reg(s)->reg(t);
}

void XtensaDecoder::formatRRR_2r(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(s)->reg(t);
}

void XtensaDecoder::formatRRR_2rr(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(r)->reg(t);
}

void XtensaDecoder::formatRRR_2imm(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->cnst(s)->cnst(t);
}

void XtensaDecoder::formatRRR_extui(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 op2 = (xbytes->opcode & 0xF00000) >> 20;
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u8 sa4 = (xbytes->opcode & 0x10000) >> 16;
    u8 sa3_0 = (xbytes->opcode & 0xF00) >> 8;
    instruction->reg(r)->reg(t)->cnst((sa4 << 4) | sa3_0)->cnst(op2 + 1);
}

void XtensaDecoder::formatRRR_1imm(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm4 = (xbytes->opcode & 0xF00) >> 8;
    instruction->cnst(imm4);
}

void XtensaDecoder::formatRRR_immr(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm4 = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t)->cnst(imm4);
}

void XtensaDecoder::formatRRR_sext(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    r_ctx->log("Operands missing @ " + String::hex(instruction->address));
}

void XtensaDecoder::formatRRR_sll(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    r_ctx->log("Operands missing @ " + String::hex(instruction->address));
}

void XtensaDecoder::formatRRR_slli(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 sa4 = (xbytes->opcode & 0x100000) >> 20;
    u8 sa3_0 = (xbytes->opcode & 0xF0) >> 4;
    u8 sa = (sa4 << 4) | sa3_0;
    instruction->reg(r)->reg(s)->cnst( sa);
}

void XtensaDecoder::formatRRR_srai(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 sa4 = (xbytes->opcode & 0x100000) >> 20;
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 sa3_0 = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u8 sa = (sa4 << 4) | sa3_0;
    instruction->reg(r)->reg(t)->cnst(sa);
}

void XtensaDecoder::formatRRR_sh(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u8 sa = (xbytes->opcode & 0xF00) >> 8;
    instruction->reg(r)->reg(t)->cnst(sa);
}

void XtensaDecoder::formatRRR_ssa(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    r_ctx->log("Operands missing @ " + String::hex(instruction->address));
}

void XtensaDecoder::formatRRR_ssai(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    r_ctx->log("Operands missing @ " + String::hex(instruction->address));
}

void XtensaDecoder::formatRRI8(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t)->reg(s)->imm(imm8);
}

void XtensaDecoder::formatRRI8_addmi(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t)->reg(s)->cnst(imm8 << 8);
}

void XtensaDecoder::formatRRI8_b(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(s)->reg(t)->tgt(instruction->address + imm8 + 4);
}

void XtensaDecoder::formatRRI8_bb(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(s)->cnst(t)->tgt(instruction->address + imm8 + 4);
}

void XtensaDecoder::formatRRI8_i12(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u16 imm12__7_0 = (xbytes->opcode & 0xFF0000) >> 16;
    u16 imm12__11_8 = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t)->cnst(Utils::signext((imm12__11_8 << 8) | imm12__7_0, 12));
}

void XtensaDecoder::formatRRI8_disp(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t)->reg(s)->cnst(imm8);
}

void XtensaDecoder::formatRRI8_disp16(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    r_ctx->log("Operands missing @ " + String::hex(instruction->address));
}

void XtensaDecoder::formatRRI8_disp32(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s8 imm8 = (xbytes->opcode & 0xFF0000) >> 16;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;

    instruction->reg(t)->disp(s, (imm8 << 2));
}

void XtensaDecoder::formatRI16(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u16 imm16 = (xbytes->opcode & 0xFFFF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    u32 dest = (0xFFFF0000 | imm16) << 2;
    instruction->reg(t)->mem(dest + static_cast<u32>(((instruction->address + 3) & 0xFFFFFFFC)));
}

void XtensaDecoder::formatRSR(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 sr = (xbytes->opcode & 0xFF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t)->reg(sr, 1);
}

void XtensaDecoder::formatRSR_spec(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t);
}

void XtensaDecoder::formatCALL(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s32 target = Utils::signext(static_cast<s32>((xbytes->opcode & 0xFFFFFFC0) >> 6), 18);
    target += instruction->address + 4;

    instruction->tgt(target);
}

void XtensaDecoder::formatCALL_sh(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s32 target = Utils::signext((xbytes->opcode & 0xFFFFC0) >> 6, 18);
    instruction->tgt((instruction->address & 0xFFFFFFFC) + (target << 2) + 4);
}

void XtensaDecoder::formatCALLX(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    instruction->reg(s);
}

void XtensaDecoder::formatBRI8_imm(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s8 imm8 = Utils::signext((xbytes->opcode & 0xFF0000) >> 16, 8);
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    instruction->reg(s)->imm(r)->tgt(instruction->address + imm8 + 4);
}

void XtensaDecoder::formatBRI8_immu(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s8 imm8 = Utils::signext((xbytes->opcode & 0xFF0000) >> 16, 8);
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    instruction->reg(s)->imm(r)->tgt(instruction->address + imm8 + 4);
}

void XtensaDecoder::formatBRI12(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    s16 imm12 = Utils::signext((xbytes->opcode & 0xFFF000) >> 12, 12);
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    instruction->reg(s)->tgt(instruction->address + imm12 + 4);
}

void XtensaDecoder::formatRRRN(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(r)->reg(s)->reg(t);
}

void XtensaDecoder::formatRRRN_disp(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm4 = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(t)->reg(s)->cnst(imm4);
}

void XtensaDecoder::formatRRRN_addi(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 r = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 t = (xbytes->opcode & 0xF0) >> 4;
    instruction->reg(r)->reg(s)->imm(t);
}

void XtensaDecoder::formatRRRN_2r(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    r_ctx->log("Operands missing @ " + String::hex(instruction->address));
}

void XtensaDecoder::formatRI7(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm7__3_0 = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 imm7__6_4 = (xbytes->opcode & 0x70) >> 4;
    instruction->reg(s)->cnst((imm7__6_4 << 4) | imm7__3_0);
}

void XtensaDecoder::formatRI6(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    u8 imm6__3_0 = (xbytes->opcode & 0xF000) >> 12;
    u8 s = (xbytes->opcode & 0xF00) >> 8;
    u8 imm6__5_4 = (xbytes->opcode & 0x30) >> 4;
    instruction->reg(s)->tgt(instruction->address + (static_cast<s8>((imm6__5_4 << 4) | imm6__3_0)) + 4);
}

void XtensaDecoder::formatRI12S3(Instruction *instruction, const XTensaOpcodeBytes *xbytes, const XtensaInstructionDefinition *def) const
{
    r_ctx->log("Operands missing @ " + String::hex(instruction->address));
}
