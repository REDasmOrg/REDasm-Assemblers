#include "arch.h"
#include <unordered_map>
#include <functional>

typedef std::function<Capstone*(RDContext*)> CapstoneEntry;
typedef std::pair<const char*, CapstoneEntry> CapstoneItem;
std::unordered_map<size_t, CapstoneItem> CS_ITEMS;

static size_t hashArch(size_t arch, size_t mode)
{
    size_t h = 0;
    RD_HashCombine(&h, arch);
    RD_HashCombine(&h, mode);
    return h;
}

static void initUserData()
{
    CS_ITEMS[hashArch(RD_ARCH_METAARM, CS_MODE_LITTLE_ENDIAN)] = { ARMLE_USERDATA, [](RDContext* ctx) { return new ARMLE(ctx); } };
    CS_ITEMS[hashArch(RD_ARCH_METAARM, CS_MODE_BIG_ENDIAN)] = { ARMBE_USERDATA, [](RDContext* ctx) { return new ARMBE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)] = { ARM64LE_USERDATA, [](RDContext* ctx) { return new ARM64LE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN)] = { ARM64BE_USERDATA, [](RDContext* ctx) { return new ARM64BE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN)] = { ARM32LE_USERDATA, [](RDContext* ctx) { return new ARM32LE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_BIG_ENDIAN)] = { ARM32BE_USERDATA, [](RDContext* ctx) { return new ARM32BE(ctx); } };

    // Editing
    CS_ITEMS[hashArch(CS_ARCH_ALL, CS_MODE_LITTLE_ENDIAN)] = { MOS65XXLE_USERDATA, [](RDContext* ctx) { return new MOS65XXLE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ALL, CS_MODE_BIG_ENDIAN)] = { MOS65XXBE_USERDATA, [](RDContext* ctx) { return new MOS65XXBE(ctx); } };
    // End Editing

    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)] = { THUMB32LE_USERDATA, [](RDContext* ctx) { return new ThumbLE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN)] = { THUMB32BE_USERDATA, [](RDContext* ctx) { return new ThumbBE(ctx); } };
}

template<size_t Arch, size_t Mode>
static Capstone* getCapstone(RDContext* ctx)
{
    auto it = CS_ITEMS.find(hashArch(Arch, Mode));
    if(it == CS_ITEMS.end()) return nullptr;

    auto* capstone = reinterpret_cast<Capstone*>(RDContext_GetUserData(ctx, it->second.first));

    if(!capstone)
    {
        capstone = it->second.second(ctx);
        RDContext_SetUserData(ctx, it->second.first, reinterpret_cast<uintptr_t>(capstone));
    }

    return capstone;
}

template<size_t Arch, size_t Mode>
static void emulate(RDContext* ctx, RDEmulateResult* result)
{
    auto* capstone = getCapstone<Arch, Mode>(ctx);
    if(capstone) capstone->emulate(result);
}

template<size_t Arch, size_t Mode>
static void render(RDContext* ctx, const RDRendererParams* rp)
{
    auto* capstone = getCapstone<Arch, Mode>(ctx);
    if(capstone) capstone->render(rp);
}

template<size_t Arch, size_t Mode>
static void lift(RDContext* ctx, rd_address address, const RDBufferView* view, RDILFunction* il)
{
    auto* capstone = getCapstone<Arch, Mode>(ctx);
    if(capstone) capstone->lift(capstone, address, view, il);
}

void rdplugin_init(RDContext*, RDPluginModule* pm)
{
    initUserData();

    RD_PLUGIN_ENTRY(RDEntryAssembler, armbe, "ARM (Big Endian)");
    armbe.emulate = &emulate<RD_ARCH_METAARM, CS_MODE_BIG_ENDIAN>;
    armbe.renderinstruction = &render<RD_ARCH_METAARM, CS_MODE_BIG_ENDIAN>;
    armbe.lift = &lift<RD_ARCH_METAARM, CS_MODE_BIG_ENDIAN>;
    armbe.bits = 64;
    RDAssembler_Register(pm, &armbe);

    RD_PLUGIN_ENTRY(RDEntryAssembler, armle, "ARM (Little Endian)");
    armle.emulate = &emulate<RD_ARCH_METAARM, CS_MODE_LITTLE_ENDIAN>;
    armle.renderinstruction = &render<RD_ARCH_METAARM, CS_MODE_LITTLE_ENDIAN>;
    armle.lift = &lift<RD_ARCH_METAARM, CS_MODE_LITTLE_ENDIAN>;
    armle.bits = 64;
    RDAssembler_Register(pm, &armle);

    RD_PLUGIN_ENTRY(RDEntryAssembler, arm64le, "ARM64 (Little Endian)");
    arm64le.emulate = &emulate<CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN>;
    arm64le.renderinstruction = &render<CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN>;
    arm64le.lift = &lift<CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN>;
    arm64le.bits = 64;
    RDAssembler_Register(pm, &arm64le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, arm64be, "ARM64 (Big Endian)");
    arm64be.emulate = &emulate<CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN>;
    arm64be.renderinstruction = &render<CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN>;
    arm64be.lift = &lift<CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN>;
    arm64be.bits = 64;
    RDAssembler_Register(pm, &arm64be);

    RD_PLUGIN_ENTRY(RDEntryAssembler, arm32le, "ARM32 (Little Endian)");
    arm32le.emulate = &emulate<CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN>;
    arm32le.renderinstruction = &render<CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN>;
    arm32le.lift = &lift<CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN>;
    arm32le.bits = 32;
    RDAssembler_Register(pm, &arm32le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, arm32be, "ARM32 (Big Endian)");
    arm32be.emulate = &emulate<CS_ARCH_ARM, CS_MODE_BIG_ENDIAN>;
    arm32be.renderinstruction = &render<CS_ARCH_ARM, CS_MODE_BIG_ENDIAN>;
    arm32be.lift = &lift<CS_ARCH_ARM, CS_MODE_BIG_ENDIAN>;
    arm32be.bits = 32;
    RDAssembler_Register(pm, &arm32be);

    // Editing
    
    RD_PLUGIN_ENTRY(RDEntryAssembler, mos65xxbe, "MOS65xxx (Big Endian)");
    mos65xxbe.emulate = &emulate<CS_ARCH_ALL, CS_MODE_BIG_ENDIAN>;
    mos65xxbe.renderinstruction = &render<CS_ARCH_ARM, CS_MODE_BIG_ENDIAN>;
    mos65xxbe.lift = &lift<CS_ARCH_ALL, CS_MODE_BIG_ENDIAN>;
    mos65xxbe.bits = 8;
    RDAssembler_Register(pm, &mos65xxbe);


    RD_PLUGIN_ENTRY(RDEntryAssembler, mos65xxle, "MOS65xxx (Little Endian)");
    mos65xxle.emulate = &emulate<CS_ARCH_ALL, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    mos65xxle.renderinstruction = &render<CS_ARCH_ALL, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    mos65xxle.lift = &lift<CS_ARCH_ALL, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    mos65xxle.bits = 8;
    RDAssembler_Register(pm, &mos65xxle);
    

    // Editing Ended

    RD_PLUGIN_ENTRY(RDEntryAssembler, thumble, "THUMB (Little Endian)");
    thumble.emulate = &emulate<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    thumble.renderinstruction = &render<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    thumble.lift = &lift<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    thumble.bits = 16;
    RDAssembler_Register(pm, &thumble);

    RD_PLUGIN_ENTRY(RDEntryAssembler, thumbbe, "THUMB (Big Endian)");
    thumbbe.emulate = &emulate<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN>;
    thumbbe.renderinstruction = &render<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN>;
    thumbbe.lift = &lift<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN>;
    thumbbe.bits = 16;
    RDAssembler_Register(pm, &thumbbe);
}

void rdplugin_free(RDContext* ctx)
{
    for(const auto& [h, item] : CS_ITEMS)
    {
        auto* capstone = reinterpret_cast<Capstone*>(RDContext_GetUserData(ctx, item.first));
        if(capstone) delete capstone;
    }
}
