#pragma once

#define THUMBLE_USERDATA    "thumble_userdata"
#define THUMBBE_USERDATA    "thumbbe_userdata"

#include "../capstone.h"

class Thumb: public Capstone
{
    public:
        Thumb(RDContext* ctx, cs_mode mode);

    public:
        void emulate(RDEmulateResult* result) override;
        void render(const RDRendererParams* rp) override;
};

class ThumbLE: public Thumb { public: ThumbLE(RDContext* ctx); };
class ThumbBE: public Thumb { public: ThumbBE(RDContext* ctx); };
