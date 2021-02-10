#pragma once

#include <rdapi/rdapi.h>
#include "mips_decoder.h"

class MIPSLifter
{
    public:
        MIPSLifter() = delete;
        template<Swap32_Callback Swap> static void lift(RDContext*, rd_address address, const RDBufferView* view, RDILFunction* il);
        static void lift(RDILFunction* il, const MIPSDecodedInstruction* decoded, rd_address address);
};

template<Swap32_Callback Swap>
void MIPSLifter::lift(RDContext*, rd_address address, const RDBufferView* view, RDILFunction* il) {
    MIPSDecodedInstruction decoded;
    if(MIPSDecoder::decode<Swap>(view, &decoded) && decoded.opcode) MIPSLifter::lift(il, &decoded, address);
    else RDILFunction_Append(il, RDILFunction_UNKNOWN(il));
}
