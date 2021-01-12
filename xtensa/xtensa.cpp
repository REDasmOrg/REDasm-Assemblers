#include "xtensa.h"
#include "xtensa_gnu.h"

#define XTENSAGNU_USERDATA "xtensa_gnu"

template<Swap32_Callback Swap>
std::unordered_map<std::string, typename Xtensa<Swap>::XtensaInfo> Xtensa<Swap>::m_info;

template<Swap32_Callback Swap>
void Xtensa<Swap>::initialize()
{
    if(!m_info.empty()) return;

    m_info["j"]       = { Theme_Jump, &Xtensa::emulateJUMP };
    m_info["ball"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bany"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bany"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bbc"]     = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bbci"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bbci.l"]  = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bbs"]     = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bbsi"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bbsi.l"]  = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["beq"]     = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["beqi"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["beqz"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["beqz.n"]  = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bf"]      = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bge"]     = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bgei"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bgeu"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bgeui"]   = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bgez"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["blt"]     = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["blti"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bltu"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bltui"]   = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bltz"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bnall"]   = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bne"]     = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bnei"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bnez"]    = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bnez.n"]  = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["bnone"]   = { Theme_JumpCond, &Xtensa::emulateBRANCH };
    m_info["call0"]   = { Theme_Call, &Xtensa::emulateCALL };
    m_info["call4"]   = { Theme_Call, &Xtensa::emulateCALL };
    m_info["call8"]   = { Theme_Call, &Xtensa::emulateCALL };
    m_info["call12"]  = { Theme_Call, &Xtensa::emulateCALL };
    m_info["callX0"]  = { Theme_Call, &Xtensa::emulateCALL };
    m_info["callX4"]  = { Theme_Call, &Xtensa::emulateCALL };
    m_info["callX8"]  = { Theme_Call, &Xtensa::emulateCALL };
    m_info["callX12"] = { Theme_Call, &Xtensa::emulateCALL };
    m_info["ret"]     = { Theme_Ret, &Xtensa::emulateRET };
    m_info["ret.n"]   = { Theme_Ret, &Xtensa::emulateRET };
    m_info["ill"]     = { Theme_Default, &Xtensa::emulateRET };
    m_info["break"]   = { Theme_Default, &Xtensa::emulateRET };
    m_info["break-n"] = { Theme_Default, &Xtensa::emulateRET };
}

template<Swap32_Callback Swap>
void Xtensa<Swap>::emulate(RDContext* ctx, RDEmulateResult* result)
{
    auto* gnu = reinterpret_cast<XtensaGnu*>(RDContext_GetUserData(ctx, XTENSAGNU_USERDATA));
    auto* view = RDEmulateResult_GetView(result);

    XtensaInstruction xinstr;
    xinstr.address = RDEmulateResult_GetAddress(result);

    int len = gnu->decode<Swap>(view, &xinstr);
    if(!len) return;

    RDEmulateResult_SetSize(result, static_cast<size_t>(len));

    auto it = m_info.find(xinstr.mnemonic);

    if((it != m_info.end()) && it->second.cb)
    {
        it->second.cb(ctx, result, &xinstr);
        return;
    }

    for(int i = 0; i < xinstr.opcount; i++)
    {
        auto& op = xinstr.operands[i];

        if(op.type == XtensaOperandType_Immediate)
            RDEmulateResult_AddReference(result, op.u_value);
    }
}

template<Swap32_Callback Swap>
void Xtensa<Swap>::render(RDContext* ctx, const RDRendererParams* rp)
{
    auto* gnu = reinterpret_cast<XtensaGnu*>(RDContext_GetUserData(ctx, XTENSAGNU_USERDATA));

    XtensaInstruction xinstr;
    xinstr.address = rp->address;
    if(!gnu->decode<Swap>(&rp->view, &xinstr)) return;

    auto it = m_info.find(xinstr.mnemonic);
    if(it != m_info.end()) RDRenderer_Mnemonic(rp->renderer, xinstr.mnemonic, it->second.theme);
    else RDRenderer_Mnemonic(rp->renderer, xinstr.mnemonic, Theme_Default);

    RDRenderer_Text(rp->renderer, " ");

    for(int i = 0; i < xinstr.opcount; i++)
    {
        if(i) RDRenderer_Text(rp->renderer, ", ");

        auto& op = xinstr.operands[i];

        switch(op.type)
        {
            case XtensaOperandType_Constant: RDRenderer_Signed(rp->renderer, op.s_value); break;
            case XtensaOperandType_Immediate: RDRenderer_Unsigned(rp->renderer, op.u_value); break;

            case XtensaOperandType_Register:
                if(!op.reg.empty()) RDRenderer_Register(rp->renderer, op.reg.c_str());
                else RDRenderer_Text(rp->renderer, "reg?");
                break;

            default: RDRenderer_Text(rp->renderer, "???"); break;
        }
    }
}

template<Swap32_Callback Swap>
void Xtensa<Swap>::emulateJUMP(RDContext*, RDEmulateResult* result, const XtensaInstruction* xinstr)
{
    if(xinstr->operands[0].type == XtensaOperandType_Immediate)
        RDEmulateResult_AddBranch(result, xinstr->operands[0].u_value);
    else
        RDEmulateResult_AddBranchUnresolved(result);
}

template<Swap32_Callback Swap>
void Xtensa<Swap>::emulateBRANCH(RDContext*, RDEmulateResult* result, const XtensaInstruction* xinstr)
{
    if(xinstr->opcount < 2)
    {
        rd_log("Unhandled branch @ " + rd_tohex(xinstr->address));
        return;
    }

    if(xinstr->operands[xinstr->opcount - 1].type == XtensaOperandType_Immediate)
        RDEmulateResult_AddBranch(result, xinstr->operands[xinstr->opcount - 1].u_value);
    else
        RDEmulateResult_AddBranchUnresolved(result);

    RDEmulateResult_AddBranchFalse(result, xinstr->address + xinstr->size);
}

template<Swap32_Callback Swap>
void Xtensa<Swap>::emulateCALL(RDContext*, RDEmulateResult* result, const XtensaInstruction* xinstr)
{
    if(xinstr->operands[0].type == XtensaOperandType_Immediate)
        RDEmulateResult_AddCall(result, xinstr->operands[0].u_value);
    else
        RDEmulateResult_AddCallUnresolved(result);
}

template<Swap32_Callback Swap>
void Xtensa<Swap>::emulateRET(RDContext*, RDEmulateResult* result, const XtensaInstruction*) { RDEmulateResult_AddReturn(result); }

void rdplugin_init(RDContext* ctx, RDPluginModule* m)
{
    Xtensa<&RD_FromLittleEndian32>::initialize();
    Xtensa<&RD_FromBigEndian32>::initialize();
    RDContext_SetUserData(ctx, XTENSAGNU_USERDATA, reinterpret_cast<uintptr_t>(new XtensaGnu()));

    RD_PLUGIN_ENTRY(RDEntryAssembler, xtensale, "Xtensa (Little Endian)");
    xtensale.emulate = &Xtensa<&RD_FromLittleEndian32>::emulate;
    xtensale.renderinstruction = &Xtensa<&RD_FromLittleEndian32>::render;
    xtensale.bits = 32;
    RDAssembler_Register(m ,&xtensale);

    RD_PLUGIN_ENTRY(RDEntryAssembler, xtensabe, "Xtensa (Big Endian)");
    xtensabe.emulate = &Xtensa<&RD_FromBigEndian32>::emulate;
    xtensabe.renderinstruction = &Xtensa<&RD_FromBigEndian32>::render;
    xtensabe.bits = 32;
    RDAssembler_Register(m ,&xtensabe);
}

void rdplugin_free(RDContext* ctx)
{
    auto* gnu = reinterpret_cast<XtensaGnu*>(RDContext_GetUserData(ctx, XTENSAGNU_USERDATA));
    if(gnu) delete gnu;
}
