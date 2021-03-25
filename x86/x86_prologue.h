#pragma once

#include <rdapi/rdapi.h>
#include <unordered_set>
#include <vector>

class X86Prologue
{
    public:
        X86Prologue(RDContext* ctx);
        void search();

    private:
        std::vector<std::string> getPrologues() const;
        void searchPrologue(rd_address address);

    private:
        std::unordered_set<rd_address> m_doneprologues;
        std::string m_currprologue;
        RDContext* m_context;
        RDDocument* m_document;
};

