// mos65xx.cpp
#include "mos65xx.h"

MOS65XX::MOS65XX(RDContext* ctx, cs_mode mode): Capstone(ctx, CS_ARCH_MOS65XX, mode) { }

void MOS65XX::emulate(RDEmulateResult* result)
{

    //auto* insn = this->decode(address, RDEmulateResult_GetView(result));
    //if(!insn) return;

    // Instruction is decoded, you can use Capstone API to analyze it
    
    rd_address address = RDEmulateResult_GetAddress(result);
    if(!this->decode(address, RDEmulateResult_GetView(result))) return;
    RDEmulateResult_SetSize(result, m_insn->size);  // Next time "emulate" is called is after insn->size bytes

    const auto& mos65xx = m_insn->detail->mos65xx;

     switch(m_insn->id)
    {
      case MOS65XX_INS_BVS: {
                    RDEmulateResult_AddBranchTrue(result, mos65xx.operands[0].imm);
                    RDEmulateResult_AddBranchFalse(result, address + m_insn->size);
        return;
      }
      
      default: break;
    }
    return;
}

void MOS65XX::render(const RDRendererParams* rp)
{
  // You can render instructions here
  // auto* insn = this->decode(rp->address, &rp->view);

  const auto& mos65xx = m_insn->detail->mos65xx;


}

void MOS65XX::lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il) { MOS65XXLifter::lift(capstone, address, view, il); }


//ARMLE::ARMLE(RDContext* ctx): ARM(ctx, CS_MODE_LITTLE_ENDIAN) { }
//ARMBE::ARMBE(RDContext* ctx): ARM(ctx, CS_MODE_BIG_ENDIAN) { }

MOS65XXLE::MOS65XXLE(RDContext* ctx): MOS65XX(ctx, CS_MODE_LITTLE_ENDIAN) { }
MOS65XXBE::MOS65XXBE(RDContext* ctx): MOS65XX(ctx, CS_MODE_BIG_ENDIAN) { }
