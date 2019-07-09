#include "metaarm.h"
#include "../arm/arm_thumb.h"
#include "../arm/arm.h"

MetaARMAssembler::MetaARMAssembler(): ARMAbstractAssembler()
{
    m_armassembler = new ARMAssembler();
    m_thumbassembler = new ARMThumbAssembler();
    m_assembler = m_armassembler;
}

MetaARMAssembler::~MetaARMAssembler()
{
    delete m_thumbassembler;
    delete m_armassembler;
}

size_t MetaARMAssembler::bits() const { return 32; }
bool MetaARMAssembler::decode(const BufferView &view, Instruction* instruction) { return m_assembler->decode(view, instruction); }

u64 MetaARMAssembler::pc(const Instruction* instruction) const
{
    if(m_assembler == m_thumbassembler)
        return m_thumbassembler->pc(instruction);

    return m_armassembler->pc(instruction);
}

ARMAssembler *MetaARMAssembler::armAssembler() { return m_armassembler; }
ARMThumbAssembler *MetaARMAssembler::thumbAssembler() { return m_thumbassembler; }
bool MetaARMAssembler::isPC(const Operand *op) const { return m_armassembler->isPC(op); }
bool MetaARMAssembler::isLR(const Operand *op) const { return m_armassembler->isLR(op); }
bool MetaARMAssembler::isArm() const { return m_assembler == m_armassembler; }
bool MetaARMAssembler::isThumb() const { return m_assembler == m_thumbassembler; }
void MetaARMAssembler::switchToThumb() { m_assembler = m_thumbassembler; }
void MetaARMAssembler::switchToArm() { m_assembler = m_armassembler; }
