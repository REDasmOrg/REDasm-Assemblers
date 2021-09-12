#include "thumb32.h"

Thumb32::Thumb32(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_ARM, static_cast<cs_mode>(CS_MODE_THUMB | mode)) { }

void Thumb32::emulate(RDEmulateResult* result)
{

}

void Thumb32::render(const RDRendererParams* rp)
{

}

Thumb32LE::Thumb32LE(RDContext* ctx): Thumb32(ctx, CS_MODE_LITTLE_ENDIAN) { }
Thumb32BE::Thumb32BE(RDContext* ctx): Thumb32(ctx, CS_MODE_BIG_ENDIAN) { }
