#pragma once

#include <unordered_map>
#include <functional>
#include <redasm/redasm.h>

using namespace REDasm;

namespace MipsRegisterTypes { enum { Cop2Register = 0x00000001, }; }

class MipsQuirks
{
    private:
        typedef std::function<bool(u32, Instruction*)> DecodeCallback;
        typedef std::function<void(u32, Instruction*)> InstructionCallback;

    private:
        MipsQuirks() = default;
        static void initOpCodes();
        static void decodeCop2(u32 data, Instruction* instruction);
        static void decodeCtc2(u32 data, Instruction* instruction);
        static void decodeCfc2(u32 data, Instruction* instruction);
        static bool decodeCop2Opcode(u32 data, Instruction* instruction);

    public:
        static bool decode(const BufferView &view, Instruction* instruction);

    private:
        static std::unordered_map<u32, DecodeCallback> m_opcodetypes;
        static std::unordered_map<u32, InstructionCallback> m_cop2map;
};
