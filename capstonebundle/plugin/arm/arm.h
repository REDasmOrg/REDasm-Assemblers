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
};

class ARMLE: public ARM { public: ARMLE(RDContext* ctx); };
class ARMBE: public ARM { public: ARMBE(RDContext* ctx); };
