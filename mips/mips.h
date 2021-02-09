#pragma once

#include <rdapi/rdapi.h>
#include <array>
#include "mips_decoder.h"

class MIPS
{
    private:
        typedef void (*Callback_MIPSDecode)(const MIPSDecodedInstruction*, const RDRendererParams*);

    public:
        MIPS() = delete;
        static void initialize();
        template<Swap32_Callback Swap> static void emulate(RDContext*, RDEmulateResult* result);
        template<Swap32_Callback Swap> static void renderInstruction(RDContext*, const RDRendererParams* rp);

    private:
        static void emulate(const MIPSDecodedInstruction* decoded, RDEmulateResult* result);
        static void renderInstruction(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderMnemonic(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderR(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderI(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderJ(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderB(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderC0(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderC1(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderC2(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderMacro(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);
        static void renderLoadStore(const MIPSDecodedInstruction* decoded, const RDRendererParams* rp);

    private:
        static std::array<Callback_MIPSDecode, MIPSEncoding_Count> m_renderers;
};

template<Swap32_Callback Swap>
void MIPS::emulate(RDContext* ctx, RDEmulateResult* result) {
    MIPSDecodedInstruction decoded;
    const RDBufferView* view = RDEmulateResult_GetView(result);

    if(!MIPSDecoder::decode<Swap>(view, &decoded)) {
        RDEmulateResult_SetSize(result, sizeof(MIPSInstruction)); // Just skip the instruction
        rdcontext_addproblem(ctx, "Unknown instruction @ " + rd_tohex(RDEmulateResult_GetAddress(result)));
        return;
    }

    MIPS::emulate(&decoded, result);
}

template<Swap32_Callback Swap>
void MIPS::renderInstruction(RDContext*, const RDRendererParams* rp) {
    MIPSDecodedInstruction decoded;
    if(!MIPSDecoder::decode<Swap>(&rp->view, &decoded)) return;
    MIPS::renderInstruction(&decoded, rp);
}
