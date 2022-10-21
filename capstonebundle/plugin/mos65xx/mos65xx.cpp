// mos65xx.cpp
#include "mos65xx.h"

MOS65XX::MOS65XX(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_MOS65XX, mode) { }

void MOS65XX::emulate(RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);
    auto* insn = this->decode(address, RDEmulateResult_GetView(result));
    if(!insn) return;

    // Instruction is decoded, you can use Capstone API to analyze it
    
    RDContext_SetAddressAssembler(m_context, address, this->endianness() == Endianness_Big ? MOS65XXBE_ID : MOS65XXLE_ID);
    if(!this->decode(address, RDEmulateResult_GetView(result))) return;

    RDEmulateResult_SetSize(result, m_insn->size);

}

void MOS65XX::render(const RDRendererParams* rp)
{
  // You can render instructions here
  auto* insn = this->decode(rp->address, &rp->view);

}

//ARMLE::ARMLE(RDContext* ctx): ARM(ctx, CS_MODE_LITTLE_ENDIAN) { }
//ARMBE::ARMBE(RDContext* ctx): ARM(ctx, CS_MODE_BIG_ENDIAN) { }

MOS65XXLE::MOS65XXLE(RDContext* ctx): MOS65XX(ctx, CS_MODE_LITTLE_ENDIAN) { }
MOS65XXBE::MOS65XXBE(RDContext* ctx): MOS65XX(ctx, CS_MODE_BIG_ENDIAN) { }
