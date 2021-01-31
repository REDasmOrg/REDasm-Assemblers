#pragma once

#include <rdapi/rdapi.h>
#include <optional>
#include "mips_format.h"

class MIPSDecoder
{
    public:
        template<Swap32_Callback Swap> static bool decode(const RDBufferView* view, MIPSDecodedInstruction* decoded);
        static bool decodeOne(const RDBufferView* view, MIPSDecodedInstruction* decoded, Swap32_Callback swapcb);
        static std::optional<rd_address> calcAddress(const MIPSDecodedInstruction* decoded, rd_address address);
        static const char* cop0reg(u32 r);
        static const char* reg(u32 r);

    private:
        static bool decode(const RDBufferView* view, MIPSDecodedInstruction* decoded, Swap32_Callback swapcb);
        static bool checkEncoding(MIPSDecodedInstruction* decoded);
        static size_t checkFormat(const MIPSInstruction* mi);
};

template<Swap32_Callback Swap>
bool MIPSDecoder::decode(const RDBufferView* view, MIPSDecodedInstruction* decoded) {
    if(view->size < sizeof(u32)) return false;
    return MIPSDecoder::decode(view, decoded, Swap);
}
