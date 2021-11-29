#pragma once

#include <rdapi/rdapi.h>
#include <capstone/capstone.h>
#include <memory>
#include <string>
#include "capstonelifter.h"

enum: u32 {
    RD_ARCH_METAARM = CS_ARCH_ALL + 1
};

class Capstone
{
    public:
        Capstone(RDContext* ctx);
        Capstone(RDContext* ctx, cs_arch arch, cs_mode mode);
        virtual ~Capstone();
        virtual void emulate(RDEmulateResult* result) = 0;
        virtual void render(const RDRendererParams* rp) = 0;
        virtual void lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il) = 0;
        virtual const cs_insn* decode(rd_address address, const RDBufferView* view) const;
        virtual const char* regName(unsigned int reg) const;
        rd_endianness endianness() const;
        cs_arch arch() const;
        cs_mode mode() const;
        RDContext* context() const;
        CapstoneLifter* lifter() const;

    protected:
        void renderRegister(const RDRendererParams* rp, unsigned int reg) const;
        std::string instructionText() const;

    protected:
        std::unique_ptr<CapstoneLifter> m_lifter;
        RDContext* m_context;
        RDDocument* m_document;
        const char* m_userdata;
        cs_insn* m_insn{nullptr};
        cs_arch m_arch;
        cs_mode m_mode;
        csh m_handle{0};
};
