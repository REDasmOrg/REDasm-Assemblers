#pragma once

#include <rdapi/rdapi.h>
#include "mips_decoder.h"

class MIPSLifter
{
    public:
        MIPSLifter() = delete;
        template<Swap32_Callback Swap> static void lift(RDContext*, rd_address address, const RDBufferView* view, RDILFunction* il);
        static void lift(RDILFunction* il, const MIPSDecodedInstruction* decoded, const MIPSDecodedInstruction* nextdecoded, rd_address address);
};

template<Swap32_Callback Swap>
void MIPSLifter::lift(RDContext*, rd_address address, const RDBufferView* view, RDILFunction* il) {
    MIPSDecodedInstruction decoded, nextdecoded;

    if(MIPSDecoder::decode<Swap>(view, &decoded) && decoded.opcode) {
        bool isdecoded = MIPSDecoder::decode<Swap>(view, &nextdecoded) && nextdecoded.opcode;
        MIPSLifter::lift(il, &decoded, isdecoded ? &nextdecoded : nullptr, address);
    }

    else RDILFunction_Append(il, RDILFunction_UNKNOWN(il));
}
