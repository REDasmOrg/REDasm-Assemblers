#pragma once

#include "../capstone.h"
#include "../arm/common.h"

class ARM32: public Capstone
{
    public:
        ARM32(RDContext* ctx, cs_mode mode);
        void emulate(RDEmulateResult* result) override;
        void render(const RDRendererParams* rp) override;
};

class ARM32LE: public ARM32 { public: ARM32LE(RDContext* ctx); };
class ARM32BE: public ARM32 { public: ARM32BE(RDContext* ctx); };
