#pragma once

#include <rdapi/rdapi.h>
#include <forward_list>
#include <optional>
#include <array>
#include "mips_instruction.h"
#include "mips_format.h"

struct MIPSDecodedInstruction {
    MIPSInstruction instruction;
    const MIPSOpcode* opcode;
};

class MIPSDecoder
{
    private:
        typedef u32 (*Swap_Callback)(u32);
        typedef void (*Callback_MIPSDecode)(const MIPSDecodedInstruction*, const RDRenderItemParams*);

    public:
        template<Swap_Callback Swap> static void emulate(RDContext*, RDEmulateResult* result);
        template<MIPSDecoder::Swap_Callback Swap> static void renderInstruction(RDContext* ctx, const RDRenderItemParams* rip);

    private:
        template<Swap_Callback Swap> static size_t decode(const RDBufferView* view, MIPSDecodedInstruction* decoded);
        static const char* cop0reg(u32 r);
        static const char* reg(u32 r);
        static void renderR(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip);
        static void renderI(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip);
        static void renderJ(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip);
        static void renderB(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip);
        static void renderC(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip);
        static void renderLoadStore(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip);
        static void renderMnemonic(const MIPSDecodedInstruction* decoded, const RDRenderItemParams* rip);
        //static void checkLui(RDDisassembler* disassembler, const RDInstruction* instruction);
        static bool checkNop(const MIPSDecodedInstruction* decoded);
        static bool checkB(const MIPSDecodedInstruction* decoded);
        static bool checkMTC0(const MIPSDecodedInstruction* decoded);
        static size_t checkFormat(const MIPSInstruction* mi);
        static std::optional<rd_address> calcAddress(const MIPSDecodedInstruction* decoded, rd_address address);

    private:
        //static std::forward_list<RDInstruction> m_luilist;
        static std::array<Callback_MIPSDecode, MIPSEncoding_Count> m_renderers;
};
