#include "arm_plugin.h"
#include <redasm/redasm.h>
#include "metaarm/metaarm_algorithm.h"
#include "metaarm/metaarm_printer.h"
#include "metaarm/metaarm.h"
#include "arm/arm_thumb.h"
#include "arm/arm.h"

ARMProxyAssembler::ARMProxyAssembler(): Assembler() { }
size_t ARMProxyAssembler::bits() const { return m_armassembler->bits(); }

void ARMProxyAssembler::init(const AssemblerRequest &request)
{
    if(request.modeIs("armthumb"))
        m_armassembler = std::make_unique<MetaARMAssembler>();
    else if(request.modeIs("thumb"))
        m_armassembler = std::make_unique<ARMThumbAssembler>();
    else
        m_armassembler = std::make_unique<ARMAssembler>();

    m_armassembler->init(request);
}

bool ARMProxyAssembler::decode(const BufferView &view, Instruction *instruction) { return m_armassembler->decode(view, instruction); }

Algorithm *ARMProxyAssembler::doCreateAlgorithm(Disassembler *disassembler) const
{
    if(dynamic_cast<MetaARMAssembler*>(m_armassembler.get()))
        return new MetaARMAlgorithm(disassembler);

    return Assembler::doCreateAlgorithm(disassembler);
}

Printer *ARMProxyAssembler::doCreatePrinter(Disassembler *disassembler) const { return new MetaARMPrinter(disassembler); }

REDASM_ASSEMBLER("ARM", "Dax", "MIT", 1)
REDASM_LOAD { arm.plugin = new ARMProxyAssembler(); return true; }
REDASM_UNLOAD { arm.plugin->release(); }
