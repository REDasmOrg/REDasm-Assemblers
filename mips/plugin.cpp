#include "mips.h"
#include "mips_lifter.h"

void rdplugin_init(RDContext*, RDPluginModule* pm)
{
    MIPS::initialize();

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips32le, "MIPS32 (Little Endian)");
    mips32le.emulate = &MIPS::emulate<&rd_fromle32>;
    mips32le.renderinstruction = &MIPS::renderInstruction<&rd_fromle32>;
    mips32le.lift = &MIPSLifter::lift<&rd_fromle32>;
    mips32le.bits = 32;
    RDAssembler_Register(pm, &mips32le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips32be, "MIPS32 (Big Endian)");
    mips32be.emulate = &MIPS::emulate<&rd_frombe32>;
    mips32be.renderinstruction = &MIPS::renderInstruction<&rd_frombe32>;
    mips32be.lift = &MIPSLifter::lift<&rd_frombe32>;
    mips32be.bits = 32;
    RDAssembler_Register(pm, &mips32be);

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips64le, "MIPS64 (Little Endian)");
    mips64le.emulate = &MIPS::emulate<&rd_fromle32>;
    mips64le.renderinstruction = &MIPS::renderInstruction<&rd_fromle32>;
    mips64le.lift = &MIPSLifter::lift<&rd_fromle32>;
    mips64le.bits = 64;
    RDAssembler_Register(pm, &mips64le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, mips64be, "MIPS64 (Big Endian)");
    mips64be.emulate = &MIPS::emulate<&rd_frombe32>;
    mips64be.renderinstruction = &MIPS::renderInstruction<&rd_frombe32>;
    mips64be.lift = &MIPSLifter::lift<&rd_frombe32>;
    mips64be.bits = 64;
    RDAssembler_Register(pm, &mips64be);
}
