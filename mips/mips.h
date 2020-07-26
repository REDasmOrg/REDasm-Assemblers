#pragma once

#include <rdapi/rdapi.h>
#include <forward_list>
#include <unordered_map>
#include <array>
#include "mips_instruction.h"
#include "mips_format.h"

class MIPSDecoder
{
    private:
        typedef bool (*Callback_MIPSDecode)(const MIPSInstruction*, RDInstruction*);

    public:
        static const char* regname(struct RDAssemblerPlugin*, const RDInstruction*, const RDOperand*, rd_register_id r);
        template<u32 (*Swap)(u32)> static bool decode(const RDAssemblerPlugin*, RDBufferView* view, RDInstruction* instruction);
        static void emulate(const RDAssemblerPlugin*, RDDisassembler* disassembler, const RDInstruction* instruction);
        static bool render(const RDAssemblerPlugin*, RDRenderItemParams* rip);
        static void rdil(const RDAssemblerPlugin*, const RDInstruction* instruction, RDInstruction** rdil);

    private:
        static bool decodeR(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeI(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeJ(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeB(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool decodeC(const MIPSInstruction* mi, RDInstruction* instruction);
        static bool checkNop(RDInstruction* instruction);
        static void checkLui(RDDisassembler* disassembler, const RDInstruction* instruction);
        static void applyFormat(const MIPSOpcode* format, RDInstruction* instruction);
        static void processDelaySlot(RDDisassembler* disassembler, const RDInstruction* branchinstruction, const RDInstruction* delayslotinstruction);
        static size_t checkFormat(const MIPSInstruction* mi);

    private:
        static std::forward_list<RDInstruction> m_luilist;
        static std::unordered_map<rd_address, rd_address> m_delayslots; // DelaySlot | Branch
        static std::array<Callback_MIPSDecode, MIPSEncoding_Count> m_decoders;
};
