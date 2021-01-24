#pragma once

#include <rdapi/rdapi.h>
#include <capstone/capstone.h>
#include <memory>
#include <string>
#include "capstonelifter.h"

class Capstone
{
    public:
        Capstone(RDContext* ctx, cs_arch arch, cs_mode mode);
        virtual ~Capstone();
        virtual void emulate(RDEmulateResult* result) = 0;
        virtual void render(const RDRendererParams* rp) = 0;
        const cs_insn* decode(rd_address address, const RDBufferView* view) const;
        const char* regName(unsigned int reg) const;
        CapstoneLifter* lifter() const;

    protected:
        void renderRegister(const RDRendererParams* rp, unsigned int reg) const;
        std::string instructionText() const;

    protected:
        std::unique_ptr<CapstoneLifter> m_lifter;
        RDContext* m_context;
        const char* m_userdata;
        cs_insn* m_insn{nullptr};
        csh m_handle{0};
};
