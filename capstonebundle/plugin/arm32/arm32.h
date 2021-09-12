#pragma once

#define ARM32LE_USERDATA "arm32le_userdata"
#define ARM32BE_USERDATA "arm32be_userdata"

#include "../capstone.h"

class ARM32: public Capstone
{
    public:
        ARM32(RDContext* ctx, cs_mode mode);

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

class ARM32LE: public ARM32 { public: ARM32LE(RDContext* ctx); };
class ARM32BE: public ARM32 { public: ARM32BE(RDContext* ctx); };
