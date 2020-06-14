#pragma once

#include <rdapi/rdapi.h>
#include <Zydis/Zydis.h>

class X86Assembler
{
    public:
        X86Assembler(const RDPluginHeader* plugin);
        void emulate(RDDisassembler* disassembler, const RDInstruction* instruction);
        bool decode(RDBufferView* view, RDInstruction* instruction);
        bool render(RDRenderItemParams* rip);

    private:
        void categorizeInstruction(RDInstruction* instruction, const ZydisDecodedInstruction* zinstr) const;
        void writeMnemonic(RDInstruction* instruction, const ZydisDecodedInstruction* zinstr) const;
        void writeOperands(RDInstruction* instruction, const ZydisDecodedInstruction* zinstr) const;
        void writeMemoryOperand(RDOperand* operand, const ZydisDecodedOperand* zop) const;

    private:
        const RDAssemblerPlugin* m_plugin;
        ZydisFormatter m_formatter;
        ZydisDecoder m_decoder;
};
