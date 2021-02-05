#pragma once

#include <rdapi/rdapi.h>

class Capstone;

class CapstoneLifter
{
    public:
        CapstoneLifter(RDContext* ctx);
        virtual ~CapstoneLifter() = default;
        virtual void lift(const Capstone* capstone, rd_address address, const RDBufferView* view, RDILFunction* il) = 0;

    protected:
        RDContext* m_context;
};

