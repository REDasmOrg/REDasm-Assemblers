#pragma once

#define ARMLE_USERDATA "armle_userdata"
#define ARMBE_USERDATA "armbe_userdata"

#include <memory>
#include "../capstone.h"
#include "../arm64/arm64.h"
#include "../arm32/arm32.h"

class ARM: public Capstone
{
    public:
        ARM(RDContext* ctx, cs_mode mode);
        void emulate(RDEmulateResult* result) override;
        void render(const RDRendererParams* rp) override;
        const cs_insn* decode(rd_address address, const RDBufferView* view) const override;
        const char* regName(unsigned int reg) const override;

    private:
        const cs_insn* checkDecode(Capstone* capstone, rd_address address, const RDBufferView* view) const;

    private:
        std::unique_ptr<ARM64> m_arm64;
        std::unique_ptr<ARM32> m_arm32;
        mutable Capstone* m_lastarch{nullptr};
};

class ARMLE: public ARM { public: ARMLE(RDContext* ctx); };
class ARMBE: public ARM { public: ARMBE(RDContext* ctx); };
