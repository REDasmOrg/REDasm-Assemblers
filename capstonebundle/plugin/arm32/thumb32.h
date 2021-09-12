#pragma once

#define THUMBLE_USERDATA    "thumble_userdata"
#define THUMBBE_USERDATA    "thumbbe_userdata"

#include "../capstone.h"

class Thumb32: public Capstone
{
    public:
        Thumb32(RDContext* ctx, cs_mode mode);

    public:
        void emulate(RDEmulateResult* result) override;
        void render(const RDRendererParams* rp) override;
};

class Thumb32LE: public Thumb32 { public: Thumb32LE(RDContext* ctx); };
class Thumb32BE: public Thumb32 { public: Thumb32BE(RDContext* ctx); };
