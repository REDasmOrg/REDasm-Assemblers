#include "zydiscommon.h"

bool ZydisCommon::decode(ZydisDecoder decoder, const RDBufferView* view, ZydisDecodedInstruction* zinstr)
{
    return ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, view->data, static_cast<ZyanUSize>(view->size), zinstr));
}

std::optional<ZyanU64> ZydisCommon::calcAddress(const ZydisDecodedInstruction* zinstr, size_t opidx, rd_address address, bool* istable)
{
    ZyanU64 calcaddress = 0;
    auto& zop = zinstr->operands[opidx];

    switch(zop.type)
    {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
            if(!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(zinstr, &zop, address, &calcaddress)))
                return std::make_optional(zop.imm.value.u);

            return std::make_optional(calcaddress);
        }

        case ZYDIS_OPERAND_TYPE_MEMORY: {
            if(!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(zinstr, &zop, address, &calcaddress))) {
                if((zop.mem.index != ZYDIS_REGISTER_NONE) && zop.mem.disp.has_displacement) {
                    if(istable) *istable = true;
                    return std::make_optional(zop.mem.disp.value);
                }
            }
            else
                return std::make_optional(calcaddress);

            break;
        }

        default: break;
    }

    return std::nullopt;
}

ZydisRegister ZydisCommon::getSP(const RDContext* ctx)
{
    switch(RDContext_GetBits(ctx))
    {
        case 32: return ZYDIS_REGISTER_ESP;
        case 64: return ZYDIS_REGISTER_RSP;
        default: break;
    }

    return ZYDIS_REGISTER_SP;
}

ZydisRegister ZydisCommon::getBP(const RDContext* ctx)
{
    switch(RDContext_GetBits(ctx))
    {
        case 32: return ZYDIS_REGISTER_EBP;
        case 64: return ZYDIS_REGISTER_RBP;
        default: break;
    }

    return ZYDIS_REGISTER_BP;
}
