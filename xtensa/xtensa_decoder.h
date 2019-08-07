#pragma once

#include <redasm/redasm.h>
#include <list>
#include "xtensa_opcodes.h"

using namespace REDasm;

class XtensaDecoder
{
    public:
        XtensaDecoder(endianness_t endianness);
        bool decode(const BufferView &view, Instruction *instruction);

    private:
        const XtensaInstructionDefinition* findInstruction(const XTensaOpcodeBytes* xbytes) const;
        bool fetch(const BufferView &view, XTensaOpcodeBytes *xbytes) const;

    private:
        void formatRRR(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_2r(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_2rr(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_2imm(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_extui(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_1imm(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_immr(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_sext(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_sll(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_slli(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_srai(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_sh(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_ssa(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRR_ssai(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8_addmi(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8_b(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8_bb(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8_i12(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8_disp(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8_disp16(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRI8_disp32(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRI16(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRSR(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRSR_spec(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatCALL(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatCALL_sh(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatCALLX(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatBRI8_imm(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatBRI8_immu(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatBRI12(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRRN(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRRN_disp(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRRN_addi(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRRRN_2r(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRI7(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRI6(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;
        void formatRI12S3(Instruction* instruction, const XTensaOpcodeBytes* xbytes, const XtensaInstructionDefinition* def) const;

    private:
        endianness_t m_endianness;
};
