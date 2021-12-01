#pragma once

#include <rdapi/rdapi.h>
#include <utility>
#include "../capstone.h"

class ARM32Common
{
    public:
        ARM32Common() = delete;
        static void emulate(Capstone* capstone, RDEmulateResult* result, const cs_insn* insn);
        static void render(Capstone* capstone, const cs_insn* insn, const RDRendererParams* rp);
        static rd_address pc(const Capstone* capstone, const cs_insn* insn);
        static bool isMemPC(const arm_op_mem& mem);

    private:
        static void renderMemory(Capstone* capstone, const cs_arm& arm, const cs_arm_op& op, const RDRendererParams* rp);
        static void checkFlowFrom(const cs_insn* insn, RDEmulateResult* result, int startidx);
        static void processOperands(Capstone* capstone, const cs_insn* insn, RDEmulateResult* result);
        static bool isPC(const cs_insn* insn, int opidx);
        static std::pair<size_t, size_t> checkWrap(const cs_insn* insn);
        static rd_type mnemonicTheme(const cs_insn* insn);
};
