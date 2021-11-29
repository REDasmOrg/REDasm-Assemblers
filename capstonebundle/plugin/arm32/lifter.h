#pragma once

#include "../capstone.h"

class ARM32Lifter
{
    public:
        ARM32Lifter() = delete;
        static void lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il);
};

