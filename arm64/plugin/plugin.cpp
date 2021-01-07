#include "arm64.h"
#include "arm64_lifter.h"
#include <capstone/capstone.h>

void rdplugin_init(RDContext*, RDPluginModule* pm)
{
    RD_PLUGIN_ENTRY(RDEntryAssembler, arm64le, "ARM64 Assembler (Little Endian)");
    arm64le.emulate = &ARM64::emulate<CS_MODE_LITTLE_ENDIAN>;
    arm64le.renderinstruction = &ARM64::render<CS_MODE_LITTLE_ENDIAN>;
    arm64le.lift = &ARM64Lifter::lift;
    arm64le.bits = 64;
    RDAssembler_Register(pm, &arm64le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, arm64be, "ARM64 Assembler (Big Endian)");
    arm64be.emulate = &ARM64::emulate<CS_MODE_BIG_ENDIAN>;
    arm64be.renderinstruction = &ARM64::render<CS_MODE_LITTLE_ENDIAN>;
    arm64be.lift = &ARM64Lifter::lift;
    arm64be.bits = 64;
    RDAssembler_Register(pm, &arm64be);
}

void rdplugin_free(RDContext* ctx) { ARM64::free(ctx); }
