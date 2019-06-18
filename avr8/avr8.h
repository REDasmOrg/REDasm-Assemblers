#pragma once

// http://roncella.iet.unipi.it/Didattica/Corsi/Elettronica/Risorse/Atmel-0856-AVR-Instruction-Set-Manual.pdf
// Based on: https://github.com/vsergeev/vavrdisasm

#include <redasm/redasm.h>
#include <redasm/plugins/assembler/assembler.h>
#include "avr8_decoder.h"

using namespace REDasm;

class AVR8Assembler: public Assembler
{
    private:
        typedef std::function<bool(u16, Instruction*)> OpCodeCallback;

    public:
        AVR8Assembler();
        size_t bits() const override;

    private:
        void compileInstruction(Instruction* instruction, const AVR8Operand &avrop, size_t opindex);
        void decodeOperand(u32 opvalue, Instruction* instruction, const AVR8Operand& avrop, size_t opidx);

    protected:
        Printer* doCreatePrinter(Disassembler* disassembler) const override;
        bool decodeInstruction(const BufferView &view, Instruction* instruction) override;

    private:
        std::unordered_map<u16, OpCodeCallback> m_opcodes;
};
