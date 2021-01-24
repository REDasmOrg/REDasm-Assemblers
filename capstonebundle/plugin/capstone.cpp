#include "capstone.h"

Capstone::Capstone(RDContext* ctx, cs_arch arch, cs_mode mode): m_context(ctx)
{
    auto err = cs_open(arch, mode, &m_handle);

    if(err)
    {
        rd_log(cs_strerror(err));
        return;
    }

    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
    m_insn = cs_malloc(m_handle);
}

Capstone::~Capstone()
{
    if(!m_handle) return;
    cs_free(m_insn, 1);
    cs_close(&m_handle);
}

CapstoneLifter* Capstone::lifter() const { return m_lifter.get(); }
void Capstone::renderRegister(const RDRendererParams* rp, unsigned int reg) const { RDRenderer_Register(rp->renderer, this->regName(reg)); }

const cs_insn* Capstone::decode(rd_address address, const RDBufferView* view) const
{
    const auto* pdata = reinterpret_cast<const uint8_t*>(view->data);
    size_t size = view->size;
    return cs_disasm_iter(m_handle, &pdata, &size, &address, m_insn) ? m_insn : nullptr;
}

const char* Capstone::regName(unsigned int reg) const { return cs_reg_name(m_handle, reg); }
std::string Capstone::instructionText() const { return std::string(m_insn->mnemonic) + " " + std::string(m_insn->op_str);  }
