#pragma once

// Reference: https://0x04.net/~mwk/doc/xtensa.pdf

#include <rdapi/rdapi.h>
#include <list>
#include "xtensa_opcodes.h"

template<size_t endianness>
class XtensaDecoder
{
    public:
        XtensaDecoder() = delete;
        static const XtensaInstruction* decode(const RDBufferView* view);
        static void emulate(const RDAssemblerPlugin*, RDEmulateResult* result);
        static bool render(const RDAssemblerPlugin*, RDRenderItemParams* rip);

    private:
        static const XtensaInstruction* findInstruction(const XTensaOpcodeBytes* xbytes);
        static bool fetch(const RDBufferView* view, XTensaOpcodeBytes *xbytes);

    private:
        static void formatRRR(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_2r(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_2rr(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_2imm(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_extui(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_1imm(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_immr(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_sext(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_sll(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_slli(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_srai(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_sh(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_ssa(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRR_ssai(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8_addmi(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8_b(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8_bb(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8_i12(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8_disp(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8_disp16(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRI8_disp32(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRI16(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRSR(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRSR_spec(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatCALL(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatCALL_sh(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatCALLX(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatBRI8_imm(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatBRI8_immu(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatBRI12(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRRN(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRRN_disp(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRRN_addi(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRRRN_2r(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRI7(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRI6(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
        static void formatRI12S3(RDInstruction* instruction, const XTensaOpcodeBytes* xbytes);
};
