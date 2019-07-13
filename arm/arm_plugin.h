#pragma once

#include <redasm/plugins/assembler/assembler.h>

using namespace REDasm;

class ARMProxyAssembler: public Assembler
{
    public:
        ARMProxyAssembler();
        size_t bits() const override;
        void init(const AssemblerRequest &request) override;
        bool decode(const BufferView& view, Instruction *instruction) override;

    protected:
        Algorithm * doCreateAlgorithm() const override;
        Printer* doCreatePrinter() const override;

    private:
        std::unique_ptr<Assembler> m_armassembler;
};
