#include "thumb32.h"
#include "../arm/common.h"
#include "common.h"

Thumb::Thumb(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_ARM, static_cast<cs_mode>(CS_MODE_THUMB | mode)) { }

void Thumb::emulate(RDEmulateResult* result)
{
    rd_address address = ARM_PC(RDEmulateResult_GetAddress(result));
    auto* insn = this->decode(address, RDEmulateResult_GetView(result));
    if(!insn) return;

    //const auto& arm = insn->detail->arm;
    RDEmulateResult_SetSize(result, insn->size);
    ARM32Common::emulate(this, result, insn);
}

void Thumb::render(const RDRendererParams* rp)
{
    auto* insn = this->decode(ARM_PC(rp->address), &rp->view);
    if(insn) ARM32Common::render(this, rp, insn);
}

ThumbLE::ThumbLE(RDContext* ctx): Thumb(ctx, CS_MODE_LITTLE_ENDIAN) { }
ThumbBE::ThumbBE(RDContext* ctx): Thumb(ctx, CS_MODE_BIG_ENDIAN) { }
