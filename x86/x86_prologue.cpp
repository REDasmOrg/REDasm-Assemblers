#include "x86_prologue.h"

X86Prologue::X86Prologue(RDContext* ctx): m_context(ctx)
{
    m_document = RDContext_GetDocument(ctx);
}

void X86Prologue::search()
{
    const rd_address* address = nullptr;
    size_t c = RDDocument_GetSegments(m_document, &address);

    for(size_t i = 0; i < c; i++)
    {
        RDSegment segment;
        if(!RDDocument_AddressToSegment(m_document, address[i], &segment)) continue;

        if(!HAS_FLAG(&segment, SegmentFlags_Code) || HAS_FLAG(&segment, SegmentFlags_Bss)) continue;
        this->searchPrologue(segment.address);
    }
}

std::vector<std::string> X86Prologue::getPrologues() const
{
    if(RDContext_MatchAssembler(m_context, "x86_64"))
        return { "55 4889e5" };

    return { "55 8bec" }; // x86
}

void X86Prologue::searchPrologue(rd_address address)
{
    m_doneprologues.clear();
    auto prologues = this->getPrologues();

    for(const auto& p : prologues)
    {
        m_currprologue = p;

        RDDocument_EachBlock(m_document, address, [](const RDBlock* b, void* userdata) {
            if(!IS_TYPE(b, BlockType_Unknown)) return true;
            auto* thethis = reinterpret_cast<X86Prologue*>(userdata);

            RDBufferView view;
            if(!RDDocument_GetBlockView(thethis->m_document, b->address, &view)) return true;

            while(u8* p = RDBufferView_FindPatternNext(&view, thethis->m_currprologue.c_str())) {
                auto loc = RD_AddressOf(thethis->m_context, p);
                if(!loc.valid) continue;
                rd_status("Found prologue @ " + rd_tohex(loc.address));
                thethis->m_doneprologues.insert(loc.address);
            }

            return true;
        }, this);
    }

    for(rd_address address : m_doneprologues)
        RDDocument_CreateFunction(m_document, address, nullptr);
}
