// capstone.h
#include "../capstone.h"

class MOS65XX: public Capstone {
  public:
    Capstone(RDContext* ctx); // There is also a "cs_mode" argument, I don't know if this architecture needs it
    void emulate(RDEmulateResult* result) override; // This implements the algorithm (jumps, calls etc)
    void render(const RDRendererParams* rp) override; // This renders instructions visually
};