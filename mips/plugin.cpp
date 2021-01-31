#include "mips.h"

void rdplugin_init(RDContext*, RDPluginModule* pm)
{
    MIPS::initialize();

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips32le, "MIPS32 (Little Endian)");
    mips32le.emulate = &MIPS::emulate<&rd_fromle32>;
    mips32le.renderinstruction = &MIPS::renderInstruction<&rd_fromle32>;
    mips32le.bits = 32;
    RDAssembler_Register(pm, &mips32le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips32be, "MIPS32 (Big Endian)");
    mips32be.emulate = &MIPS::emulate<&rd_frombe32>;
    mips32be.renderinstruction = &MIPS::renderInstruction<&rd_frombe32>;
    mips32be.bits = 32;
    RDAssembler_Register(pm, &mips32be);
}
