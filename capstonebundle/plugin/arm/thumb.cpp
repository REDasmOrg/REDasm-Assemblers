#include "thumb.h"

Thumb::Thumb(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_ARM, static_cast<cs_mode>(CS_MODE_THUMB | mode)) { }

void Thumb::emulate(RDEmulateResult* result)
{

}

void Thumb::render(const RDRendererParams* rp)
{

}

ThumbLE::ThumbLE(RDContext* ctx): Thumb(ctx, CS_MODE_LITTLE_ENDIAN) { }
ThumbBE::ThumbBE(RDContext* ctx): Thumb(ctx, CS_MODE_BIG_ENDIAN) { }
