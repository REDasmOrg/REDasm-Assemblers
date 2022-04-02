#include "arm32.h"
#include "common.h"
#include "arm32_lifter.h"

ARM32::ARM32(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_ARM, mode) { }

void ARM32::emulate(RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);

    RDContext_SetAddressAssembler(m_context, address, this->endianness() == Endianness_Big ? ARM32BE_ID : ARM32LE_ID);
    if(!this->decode(address, RDEmulateResult_GetView(result))) return;

    RDEmulateResult_SetSize(result, m_insn->size);
    ARM32Common::emulate(this, result, m_insn);
}

void ARM32::render(const RDRendererParams* rp)
{
    auto* insn = this->decode(rp->address, &rp->view);
    if(insn) ARM32Common::render(this, insn, rp);
}

void ARM32::lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il) { ARM32Lifter::lift(capstone, address, view, il); }

ARM32LE::ARM32LE(RDContext* ctx): ARM32(ctx, CS_MODE_LITTLE_ENDIAN) { }
ARM32BE::ARM32BE(RDContext* ctx): ARM32(ctx, CS_MODE_BIG_ENDIAN) { }
