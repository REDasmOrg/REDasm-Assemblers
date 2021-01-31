#pragma once

#include "mips_format.h"
#include <functional>

class MIPSMacroDecoder
{
    private:
        typedef std::function<bool(RDBufferView*, MIPSDecodedInstruction*)> DecodeCallback;

    public:
        MIPSMacroDecoder() = delete;
        static void checkMacro(MIPSDecodedInstruction* decoded, const RDBufferView* view, Swap32_Callback swapcb);

    private:
        static void checkLui(MIPSDecodedInstruction* luidecoded, RDBufferView view, Swap32_Callback swapcb);
        static void checkLi(MIPSDecodedInstruction* decoded);
        static void checkMtc0(MIPSDecodedInstruction* decoded);
        static void checkMove(MIPSDecodedInstruction* decoded);
        static void checkNop(MIPSDecodedInstruction* decoded);
        static void checkB(MIPSDecodedInstruction* decoded);

    private:
        static bool canSimplifyLui(const MIPSDecodedInstruction* luidecoded, const MIPSDecodedInstruction* decoded);
        static void applyMacro(const std::string& mnemonic, MIPSDecodedInstruction* decoded);
};

