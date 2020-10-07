#pragma once

#include <rdapi/rdapi.h>
#include <Zydis/Zydis.h>
#include <optional>

class ZydisCommon
{
    public:
        ZydisCommon() = default;

    protected:
        static bool decode(ZydisDecoder decoder, const RDBufferView* view, ZydisDecodedInstruction* zinstr);
        static std::optional<ZyanU64> calcAddress(const ZydisDecodedInstruction* zinstr, size_t opidx, rd_address address);
        static ZydisRegister getSP(const RDContext* ctx);
        static ZydisRegister getBP(const RDContext* ctx);
};

