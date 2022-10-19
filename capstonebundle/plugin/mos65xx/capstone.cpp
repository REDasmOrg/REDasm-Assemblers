// capstone.cpp
#include "mos65xx.h"

MOS65XX::MOS65XX(RDContext* ctx): Capstone(ctx, CS_ARCH_MOS65XX, 0) { }

void MOS65XX::emulate(RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);
    auto* insn = this->decode(address, RDEmulateResult_GetView(result));
    // Instruction is decoded, you can use Capstone API to analyze it
}

void MOS65XX::render(const RDRendererParams* rp)
{
  // You can render instructions here
}