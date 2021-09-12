#pragma once

#define THUMB32LE_USERDATA "thumb32le_userdata"
#define THUMB32BE_USERDATA "thumb32be_userdata"

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
