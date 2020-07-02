#pragma once

#include <rdapi/rdapi.h>

class X86Translator
{
    public:
        X86Translator() = delete;
        static void rdil(const RDAssemblerPlugin* plugin, const RDInstruction* instruction, RDInstruction** rdil);
};

