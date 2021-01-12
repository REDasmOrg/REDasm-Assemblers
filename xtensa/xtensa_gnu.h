#pragma once

#include "xtensa_instruction.h"
#include <rdapi/rdapi.h>

class XtensaGnu
{
    public:
        XtensaGnu();
        ~XtensaGnu();
        template<Swap32_Callback Swap> int decode(const RDBufferView* view, XtensaInstruction* xinstr);

    private:
        int decode(u32 word, XtensaInstruction* xinstr);

    private:
        xtensa_insnbuf m_insnbuf, m_slotbuf;
        xtensa_isa m_isa;
};

template<Swap32_Callback Swap>
int XtensaGnu::decode(const RDBufferView* view, XtensaInstruction* xinstr) {
    if(view->size < sizeof(u32)) return 0;
    return this->decode(Swap(*reinterpret_cast<u32*>(view->data)), xinstr);
}

