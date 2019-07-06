#pragma once

#include <redasm/buffer/bufferview.h>
#include <redasm/plugins/assembler/assembler.h>

using namespace REDasm;

class MetaARMAssemblerISA
{
    public:
        enum { ARM, Thumb };

    public:
        MetaARMAssemblerISA() = delete;
        static int classify(address_t address, const BufferView& view, Disassembler* disassembler, Assembler* armassembler);

    private:
        static bool validateBranch(const Instruction *instruction, Disassembler* disassembler);
};
