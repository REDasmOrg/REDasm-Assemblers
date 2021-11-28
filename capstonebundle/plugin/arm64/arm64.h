#pragma once

#define ARM64LE_USERDATA "arm64le_userdata"
#define ARM64BE_USERDATA "arm64be_userdata"

#include "../capstone.h"

class ARM64: public Capstone
{
    public:
        ARM64(RDContext* ctx, cs_mode mode);
        void emulate(RDEmulateResult* result) override;
        void render(const RDRendererParams* rp) override;

    private:
        void renderMemory(const cs_arm64& arm64, const cs_arm64_op& op, const RDRendererParams* rp) const;
        void renderMnemonic(const RDRendererParams* rp);
};

class ARM64LE: public ARM64 { public: ARM64LE(RDContext* ctx); };
class ARM64BE: public ARM64 { public: ARM64BE(RDContext* ctx); };
