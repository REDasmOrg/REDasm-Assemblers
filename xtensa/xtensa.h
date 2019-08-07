#pragma once

// Reference: https://0x04.net/~mwk/doc/xtensa.pdf

#include <memory>
#include <redasm/redasm.h>
#include <redasm/plugins/assembler/assembler.h>
#include "xtensa_decoder.h"

using namespace REDasm;

class XtensaAssembler: public Assembler
{
    public:
        XtensaAssembler();
        size_t bits() const override;
        void init(const AssemblerRequest &request) override;
        bool decodeInstruction(const BufferView &view, Instruction *instruction) override;

    protected:
        Printer * doCreatePrinter() const override;

    private:
        std::unique_ptr<XtensaDecoder> m_decoder;
};
