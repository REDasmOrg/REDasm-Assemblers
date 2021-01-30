#pragma once

#define ARMLE_USERDATA    "armle_userdata"
#define ARMBE_USERDATA    "armbe_userdata"

#include "../capstone.h"

class ARM: public Capstone
{
    public:
        ARM(RDContext* ctx, cs_mode mode);

    public:
        void emulate(RDEmulateResult* result) override;
        void render(const RDRendererParams* rp) override;

    protected:
        virtual rd_address pc(rd_address address) const;

    private:
        std::pair<size_t, size_t> checkWrap() const;
        bool isMemPC(const arm_op_mem& mem) const;
        void checkFlowFrom(RDEmulateResult* result, int startidx) const;
        void checkFlow(RDEmulateResult* result, int opidx) const;
        void processOperands(rd_address address, RDEmulateResult* result) const;
        void renderMemory(const cs_arm& arm, const cs_arm_op& op, const RDRendererParams* rp) const;
        rd_type mnemonicTheme() const;
        const cs_arm& arm() const;
};

class ARMLE: public ARM { public: ARMLE(RDContext* ctx); };
class ARMBE: public ARM { public: ARMBE(RDContext* ctx); };
