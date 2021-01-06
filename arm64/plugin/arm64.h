#pragma once

#define ARM64_USERDATA "arm64_capstone"

#include <rdapi/rdapi.h>
#include <capstone/capstone.h>

class ARM64
{
    public:
        ARM64() = delete;
        static void free(RDContext* ctx);
        template<cs_mode Mode> static csh init(RDContext* ctx);
        template<cs_mode Mode> static void emulate(RDContext* ctx, RDEmulateResult* result);
        template<cs_mode Mode> static void render(RDContext* ctx, const RDRendererParams* rp);

    private:
        static std::string instructionText();
        static bool decode(csh h, rd_address address, const RDBufferView* view);
        static void renderMemory(csh h, const cs_arm64& arm64, const cs_arm64_op& op, const RDRendererParams* rp);
        static void renderMnemonic(csh h, const RDRendererParams* rp);
        static void render(csh h, const RDRendererParams* rp);
        static void emulate(csh h, RDContext* ctx, RDEmulateResult* result);

    private:
        static cs_insn* m_insn;
};

template<cs_mode Mode>
void ARM64::render(RDContext* ctx, const RDRendererParams* rp) {
    csh h = static_cast<csh>(RDContext_GetUserData(ctx, ARM64_USERDATA));
    if(!h) h = ARM64::init<Mode>(ctx);
    if(h) ARM64::render(h, rp);
}

template<cs_mode Mode>
void ARM64::emulate(RDContext* ctx, RDEmulateResult* result) {
    csh h = static_cast<csh>(RDContext_GetUserData(ctx, ARM64_USERDATA));
    if(!h) h = ARM64::init<Mode>(ctx);
    if(h) ARM64::emulate(h, ctx, result);
}

template<cs_mode Mode>
csh ARM64::init(RDContext* ctx) {
    csh h;
    auto err = cs_open(CS_ARCH_ARM64, Mode, &h);

    if(err) {
        rd_log(cs_strerror(err));
        return 0;
    }

    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    m_insn = cs_malloc(h);
    RDContext_SetUserData(ctx, ARM64_USERDATA, h);
    return h;
}
