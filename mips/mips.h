#pragma once

#include <rdapi/rdapi.h>
#include <array>
#include "mips_instruction.h"
#include "mips_format.h"

class MIPSDecoder
{
    private:
        typedef bool (*Callback_MIPSDecode)(const MIPSInstruction*, RDInstruction*);

    public:
        static const char* regname(struct RDAssemblerPlugin*, const RDInstruction*, register_id_t r);
        template<u32 (*Swap)(u32)> static bool decode(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction);
        static void emulate(const RDAssemblerPlugin*, RDDisassembler* disassembler, const RDInstruction* instruction);
        static bool render(const RDAssemblerPlugin*plugin, RDRenderItemParams* rip);

    private:
        static bool decodeR(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeI(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeJ(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeB(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeC(const MIPSInstruction* mi, RDInstruction* instruction);
        static void applyFormat(const MIPSOpcode* format, RDInstruction* instruction);
        static size_t checkFormat(const MIPSInstruction* mi);
        template<typename T> static T signExtend(T t, int bits);

    private:
        static std::array<Callback_MIPSDecode, MIPSEncoding_Count> m_decoders;
};

template<typename T>
T MIPSDecoder::signExtend(T t, int bits)
{
    T m = 1;
    m <<= bits - 1;
    return (t ^ m) - m;
}
