#pragma once

#include "arm_common.h"

class ARMThumbAssembler : public ARMCommonAssembler
{
    public:
        ARMThumbAssembler();
        size_t bits() const override;
        u64 pc(const Instruction* instruction) const override;
        void init(const AssemblerRequest& req) override;
};
