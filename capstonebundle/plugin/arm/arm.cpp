#include "arm.h"
#include <iostream>

ARM::ARM(RDContext* ctx, cs_mode mode): Capstone(ctx)
{
    m_arm64 = std::make_unique<ARM64>(ctx, mode);
    m_arm32 = std::make_unique<ARM32>(ctx, mode);
}

void ARM::emulate(RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);
    auto* insn = this->decode(address, RDEmulateResult_GetView(result));
    if(insn) m_lastarch->emulate(result);
}

void ARM::render(const RDRendererParams* rp)
{
    auto* insn = this->decode(rp->address, &rp->view);
    if(insn) m_lastarch->render(rp);
}

void ARM::lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il)
{
    if(m_lastarch) m_lastarch->lift(capstone, address, view, il);
}

const cs_insn* ARM::decode(rd_address address, const RDBufferView* view) const
{
    const cs_insn* insn = this->checkDecode(m_arm64.get(), address, view);
    if(!insn) insn = this->checkDecode(m_arm32.get(), address, view);
    return insn;
}

const char* ARM::regName(unsigned int reg) const
{
    auto* rn = m_arm64->regName(reg);
    if(!rn) m_arm32->regName(reg);
    return rn;
}

const cs_insn* ARM::checkDecode(Capstone* capstone, rd_address address, const RDBufferView* view) const
{
    const cs_insn* insn = capstone->decode(address, view);
    if(insn) m_lastarch = capstone;
    return insn;
}

ARMLE::ARMLE(RDContext* ctx): ARM(ctx, CS_MODE_LITTLE_ENDIAN) { }
ARMBE::ARMBE(RDContext* ctx): ARM(ctx, CS_MODE_BIG_ENDIAN) { }
