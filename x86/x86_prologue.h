#pragma once

#include <rdapi/rdapi.h>
#include <unordered_set>

class X86Prologue
{
    public:
        X86Prologue(RDContext* ctx);
        void search();

    private:
        std::string getPrologue() const;
        void searchPrologue(const RDBlockContainer* blocks);

    private:
        std::unordered_set<rd_address> m_prologues;
        std::string m_pattern;
        RDContext* m_context;
        RDDocument* m_document;
        RDLoader* m_loader;
};

