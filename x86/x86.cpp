#include "x86.h"
#include "x86_lifter.h"
#include "x86_prologue.h"
#include <rdapi/rdapi.h>
#include <vector>

#define X86_USERDATA    "x86_userdata"
#define X86_64_USERDATA "x86_64_userdata"
#define BUFFER_SIZE     256

X86Assembler::X86Assembler(RDContext* ctx, size_t bits): ZydisCommon(), m_context(ctx)
{
    if(bits == 32) ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
    else ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&m_formatter, ZYDIS_FORMATTER_PROP_HEX_PREFIX, ZYAN_FALSE);
}

void X86Assembler::lift(rd_address address, const RDBufferView* view, RDILFunction* il) { X86Lifter::lift(m_context, m_decoder, address, view, il); }

void X86Assembler::emulate(RDEmulateResult* result)
{
    rd_address address = RDEmulateResult_GetAddress(result);
    const RDBufferView* view = RDEmulateResult_GetView(result);

    ZydisDecodedInstruction zinstr;
    if(!X86Assembler::decode(m_decoder, view, &zinstr)) return;

    RDEmulateResult_SetSize(result, zinstr.length);

    switch(zinstr.meta.category)
    {
        case ZYDIS_CATEGORY_CALL: {
            bool istable = false;
            auto calcaddress = X86Assembler::calcAddress(&zinstr, 0, address, &istable);

            if(calcaddress) {
                if(istable) RDEmulateResult_AddCallTable(result, *calcaddress, RD_NVAL);
                else RDEmulateResult_AddCall(result, *calcaddress);
            }
            else RDEmulateResult_AddCallUnresolved(result);
            break;
        }

        case ZYDIS_CATEGORY_UNCOND_BR: {
            bool istable = false;
            auto calcaddress = X86Assembler::calcAddress(&zinstr, 0, address, &istable);

            if(calcaddress) {
                if(istable) RDEmulateResult_AddBranchTable(result, *calcaddress, RD_NVAL);
                else RDEmulateResult_AddBranch(result, *calcaddress);
            }

            else RDEmulateResult_AddBranchUnresolved(result);
            break;
        }

        case ZYDIS_CATEGORY_COND_BR: {
            auto calcaddress = X86Assembler::calcAddress(&zinstr, 0, address);
            if(calcaddress) RDEmulateResult_AddBranchTrue(result, *calcaddress);
            else RDEmulateResult_AddBranchUnresolved(result);

            RDEmulateResult_AddBranchFalse(result, address + zinstr.length);
            break;
        }

        case ZYDIS_CATEGORY_SYSTEM: {
            if(zinstr.mnemonic == ZYDIS_MNEMONIC_HLT) RDEmulateResult_AddReturn(result);
            break;
        }

        case ZYDIS_CATEGORY_INTERRUPT: {
            if(zinstr.mnemonic == ZYDIS_MNEMONIC_INT3) RDEmulateResult_AddReturn(result);
            break;
        }

        case ZYDIS_CATEGORY_RET: RDEmulateResult_AddReturn(result); break;
        default: this->processRefs(&zinstr, address, result); break;
    }
}

void X86Assembler::processRefs(ZydisDecodedInstruction* zinstr, rd_address address, RDEmulateResult* result)
{
    if(zinstr->mnemonic == ZYDIS_MNEMONIC_LEA)
    {
        auto calcaddress = X86Assembler::calcAddress(zinstr, 1, address);
        if(calcaddress) RDEmulateResult_AddTable(result, *calcaddress, RD_NVAL);
        return;
    }

    for(auto i = 0; i < zinstr->operand_count; i++)
    {
        auto calcaddress = X86Assembler::calcAddress(zinstr, i, address);
        if(!calcaddress) continue;

        if(zinstr->meta.category == ZYDIS_CATEGORY_BINARY) RDEmulateResult_AddData(result, *calcaddress);
        else RDEmulateResult_AddReference(result, *calcaddress);
    }
}

void X86Assembler::renderInstruction(const RDRendererParams* srp)
{
    ZydisDecodedInstruction zinstr;
    if(!X86Assembler::decode(m_decoder, &srp->view, &zinstr)) return;

    std::vector<u8> buffer(BUFFER_SIZE);
    ZydisFormatterTokenConst* token = nullptr;

    if(!ZYAN_SUCCESS(ZydisFormatterTokenizeInstruction(&m_formatter, &zinstr, buffer.data(), buffer.size(), srp->address, &token)))
        return;

    ZydisTokenType tokentype;
    ZyanConstCharPointer tokenvalue = nullptr;

    while(token)
    {
        ZydisFormatterTokenGetValue(token, &tokentype, &tokenvalue);

        switch(tokentype)
        {
            case ZYDIS_TOKEN_ADDRESS_ABS:
            case ZYDIS_TOKEN_ADDRESS_REL:
            case ZYDIS_TOKEN_IMMEDIATE:
            case ZYDIS_TOKEN_DISPLACEMENT:
                RDRenderer_Reference(srp->renderer, static_cast<rd_location>(std::stoull(tokenvalue, nullptr, 16)));
                break;

            case ZYDIS_TOKEN_MNEMONIC:
                if(zinstr.meta.category == ZYDIS_CATEGORY_COND_BR) RDRenderer_Mnemonic(srp->renderer, tokenvalue, Theme_JumpCond);
                else if(zinstr.meta.category == ZYDIS_CATEGORY_UNCOND_BR) RDRenderer_Mnemonic(srp->renderer, tokenvalue, Theme_Jump);
                else if(zinstr.meta.category == ZYDIS_CATEGORY_CALL) RDRenderer_Mnemonic(srp->renderer, tokenvalue, Theme_Call);
                else if(zinstr.meta.category == ZYDIS_CATEGORY_RET) RDRenderer_Mnemonic(srp->renderer, tokenvalue, Theme_Ret);
                else if(zinstr.meta.category == ZYDIS_CATEGORY_NOP) RDRenderer_Mnemonic(srp->renderer, tokenvalue, Theme_Nop);
                else RDRenderer_Mnemonic(srp->renderer, tokenvalue, Theme_Default);
                break;

            case ZYDIS_TOKEN_REGISTER: RDRenderer_Register(srp->renderer, tokenvalue); break;
            default: RDRenderer_Text(srp->renderer, tokenvalue); break;
        }

        if(!ZYAN_SUCCESS(ZydisFormatterTokenNext(&token))) token = nullptr;
    }
}

template<size_t bits>
static X86Assembler* checkAssembler(RDContext* ctx)
{
    if constexpr(bits == 32)
    {
        auto* ptr = reinterpret_cast<X86Assembler*>(RDContext_GetUserData(ctx, X86_USERDATA));

        if(!ptr)
        {
            ptr = new X86Assembler(ctx, bits);
            RDContext_SetUserData(ctx, X86_USERDATA, reinterpret_cast<uintptr_t>(ptr));
        }

        return ptr;
    }
    else
    {
        auto* ptr = reinterpret_cast<X86Assembler*>(RDContext_GetUserData(ctx, X86_64_USERDATA));

        if(!ptr)
        {
            ptr = new X86Assembler(ctx, bits);
            RDContext_SetUserData(ctx, X86_64_USERDATA, reinterpret_cast<uintptr_t>(ptr));
        }

        return ptr;
    }
}

template<size_t bits> static void renderInstruction(RDContext* ctx, const RDRendererParams* rp) { checkAssembler<bits>(ctx)->renderInstruction(rp); }
template<size_t bits> static void emulate(RDContext* ctx, RDEmulateResult* result) { checkAssembler<bits>(ctx)->emulate(result); }
template<size_t bits> static void lift(RDContext* ctx, rd_address address, const RDBufferView* view, RDILFunction* il) { checkAssembler<bits>(ctx)->lift(address, view, il); }

void rdplugin_init(RDContext*, RDPluginModule* m)
{
    RD_PLUGIN_ENTRY(RDEntryAssembler, x86_32, "x86_32");
    x86_32.renderinstruction = &renderInstruction<32>;
    x86_32.emulate = &emulate<32>;
    x86_32.lift = &lift<32>;
    x86_32.bits = 32;
    RDAssembler_Register(m, &x86_32);

    RD_PLUGIN_ENTRY(RDEntryAssembler, x86_64, "x86_64");
    x86_64.renderinstruction = &renderInstruction<64>;
    x86_64.emulate = &emulate<64>;
    x86_64.lift = &lift<64>;
    x86_64.bits = 64;

    RDAssembler_Register(m, &x86_64);

    RD_PLUGIN_ENTRY(RDEntryAnalyzer, x86_prologue, "x86/x86_64 Prologue");
    x86_prologue.flags = AnalyzerFlags_Experimental | AnalyzerFlags_Selected;
    x86_prologue.description = "Search for x86/x86_64 function prologues";
    x86_prologue.order = 3000;

    x86_prologue.isenabled = [](const RDContext* ctx) {
        return RDContext_MatchAssembler(ctx, "x86*");
    };

    x86_prologue.execute = [](RDContext* ctx) {
        X86Prologue x86p(ctx);
        x86p.search();
    };

    RDAnalyzer_Register(m, &x86_prologue);
}

void rdplugin_free(RDContext* ctx)
{
    uintptr_t ptr = RDContext_GetUserData(ctx, X86_USERDATA);
    if(ptr) delete reinterpret_cast<X86Assembler*>(ptr);

    ptr = RDContext_GetUserData(ctx, X86_64_USERDATA);
    if(ptr) delete reinterpret_cast<X86Assembler*>(ptr);
}
