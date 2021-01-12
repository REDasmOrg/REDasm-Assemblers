#include "xtensa_gnu.h"

XtensaGnu::XtensaGnu()
{
    m_isa = xtensa_isa_init(nullptr, nullptr);
    if(!m_isa) return;

    m_insnbuf = xtensa_insnbuf_alloc(m_isa);
    m_slotbuf = xtensa_insnbuf_alloc(m_isa);
}

XtensaGnu::~XtensaGnu()
{
    if(!m_isa) return;

    xtensa_insnbuf_free(m_isa, m_insnbuf);
    xtensa_insnbuf_free(m_isa, m_slotbuf);
    xtensa_isa_free(m_isa);
}

int XtensaGnu::decode(u32 word, XtensaInstruction* xinstr)
{
    xtensa_insnbuf_from_chars(m_isa,
                              m_insnbuf,
                              reinterpret_cast<const u8*>(&word),
                              sizeof(u32));

    xtensa_format fmt = xtensa_format_decode(m_isa, m_insnbuf);
    if(fmt == XTENSA_UNDEFINED) return 0;

    int nslots = xtensa_format_num_slots(m_isa, fmt);

    if(nslots != 1)
    {
        rd_log("Unexpected slots count: " + std::to_string(nslots) + " @ " + rd_tohex(xinstr->address));
        return 0;
    }

    xtensa_format_get_slot(m_isa, fmt, 0, m_insnbuf, m_slotbuf);
    xtensa_opcode opcode = xtensa_opcode_decode(m_isa, fmt, 0, m_slotbuf);
    if(opcode == XTENSA_UNDEFINED) return 0;

    xinstr->id = opcode;
    xinstr->mnemonic = xtensa_opcode_name(m_isa, opcode);

    int numop = xtensa_opcode_num_operands(m_isa, opcode);
    xinstr->opcount = 0;

    for(int i = 0; (xinstr->opcount < XTENSA_MAX_OPERANDS) && (i < numop); i++)
    {
        if(!xtensa_operand_is_visible(m_isa, opcode, i)) continue;
        int opidx = xinstr->opcount;

        unsigned int val;
        xtensa_operand_get_field(m_isa, opcode, i, fmt, 0, m_slotbuf, &val);
        xtensa_operand_decode(m_isa, opcode, i, &val);

        if(xtensa_operand_is_register(m_isa, opcode, i))
        {
            xinstr->operands[opidx].type = XtensaOperandType_Register;

            int nregs = xtensa_operand_num_regs(m_isa, opcode, i);

            if(nregs > 1)
            {
                rd_log("Too many registers found: " + std::to_string(nregs) + ", @" + rd_tohex(xinstr->address));
            }
            else
            {
                xtensa_regfile rf = xtensa_operand_regfile(m_isa, opcode, i);
                xinstr->operands[opidx].reg = xtensa_regfile_shortname(m_isa, rf) + std::to_string(val);
            }
        }
        else
        {
            if(xtensa_operand_is_PCrelative(m_isa, opcode, i))
            {
                xtensa_operand_undo_reloc(m_isa, opcode, i, &val, xinstr->address);
                xinstr->operands[opidx].type = XtensaOperandType_Immediate;
                xinstr->operands[opidx].u_value = static_cast<u32>(val);
            }
            else
            {
                xinstr->operands[opidx].type = XtensaOperandType_Constant;
                xinstr->operands[opidx].s_value = static_cast<s32>(val);
            }
        }

        xinstr->opcount++;
    }

    xinstr->size = xtensa_format_length(m_isa, fmt);
    return xinstr->size;
}
