#include "arm.h"

ARM::ARM(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_ARM, mode)
{

}

void ARM::emulate(RDEmulateResult* result)
{

}

void ARM::render(const RDRendererParams* rp)
{

}

ARMLE::ARMLE(RDContext* ctx): ARM(ctx, CS_MODE_LITTLE_ENDIAN) { }
ARMBE::ARMBE(RDContext* ctx): ARM(ctx, CS_MODE_BIG_ENDIAN) { }
