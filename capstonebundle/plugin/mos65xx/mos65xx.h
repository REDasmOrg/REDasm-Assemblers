// mos65xx.h
#pragma once

#define MOS65XXLE_USERDATA "mos65xxle_userdata" 
#define MOS65XXBE_USERDATA "mos65xxbe_userdata" 

#define MOS65XXLE_ID "mos65xxle"
#define MOS65XXBE_ID "mos65xxbe"

#include <rdapi/rdapi.h>
#include <utility>
#include "../capstone.h"

class MOS65XX: public Capstone {
  public:
    // Capstone(RDContext* ctx); // There is also a "cs_mode" argument, I don't know if this architecture needs it
    MOS65XX(RDContext* ctx, cs_mode mode);
    void emulate(RDEmulateResult* result) override; // This implements the algorithm (jumps, calls etc)
    void render(const RDRendererParams* rp) override; // This renders instructions visually
    void lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il) override;
};


class MOS65XXLifter
{
    public:
        MOS65XXLifter() = delete;
        static void lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il);

    private:
        static RDILExpression* liftOperand(const Capstone* capstone, rd_address address, const cs_insn* insn, size_t idx, const RDILFunction* il);
};


class MOS65XXLE: public MOS65XX { public: MOS65XXLE(RDContext* ctx); };
class MOS65XXBE: public MOS65XX { public: MOS65XXBE(RDContext* ctx); };