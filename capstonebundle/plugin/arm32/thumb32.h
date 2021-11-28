#pragma once

#define THUMB32LE_USERDATA "thumb32le_userdata"
#define THUMB32BE_USERDATA "thumb32be_userdata"

#include "../capstone.h"

class Thumb: public Capstone
{
    public:
        Thumb(RDContext* ctx, cs_mode mode);
        void emulate(RDEmulateResult* result) override;
        void render(const RDRendererParams* rp) override;
};

class ThumbLE: public Thumb { public: ThumbLE(RDContext* ctx); };
class ThumbBE: public Thumb { public: ThumbBE(RDContext* ctx); };
