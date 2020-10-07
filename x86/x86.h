#pragma once

#include "zydiscommon.h"

class X86Assembler: public ZydisCommon
{
    public:
        X86Assembler(RDContext* ctx);
        void lift(rd_address address, const RDBufferView* view, RDILFunction* il);
        void renderInstruction(const RDRenderItemParams* rip);
        void emulate(RDEmulateResult* result);

    private:
        void processRefs(ZydisDecodedInstruction* zinstr, rd_address address, RDEmulateResult* result);

    private:
        RDContext* m_context;
        ZydisFormatter m_formatter;
        ZydisDecoder m_decoder;
};
