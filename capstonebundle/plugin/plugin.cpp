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
    CS_ITEMS[hashArch(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)] = { ARM64LE_USERDATA, [](RDContext* ctx) { return new ARM64LE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN)] = { ARM64BE_USERDATA, [](RDContext* ctx) { return new ARM64BE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN)] = { ARM32LE_USERDATA, [](RDContext* ctx) { return new ARM32LE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_BIG_ENDIAN)] = { ARM32BE_USERDATA, [](RDContext* ctx) { return new ARM32BE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)] = { THUMB32LE_USERDATA, [](RDContext* ctx) { return new Thumb32LE(ctx); } };
    CS_ITEMS[hashArch(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN)] = { THUMB32BE_USERDATA, [](RDContext* ctx) { return new Thumb32BE(ctx); } };
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
    if(!capstone) return;

    auto* lifter = capstone->lifter();
    if(lifter) lifter->lift(capstone, address, view, il);
}

void rdplugin_init(RDContext*, RDPluginModule* pm)
{
    initUserData();

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

    RD_PLUGIN_ENTRY(RDEntryAssembler, thumb32le, "ARM32/THUMB (Little Endian)");
    thumb32le.emulate = &emulate<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    thumb32le.renderinstruction = &render<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    thumb32le.lift = &lift<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN>;
    thumb32le.bits = 16;
    RDAssembler_Register(pm, &thumb32le);

    RD_PLUGIN_ENTRY(RDEntryAssembler, thumb32be, "ARM32/THUMB (Big Endian)");
    thumb32be.emulate = &emulate<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN>;
    thumb32be.renderinstruction = &render<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN>;
    thumb32be.lift = &lift<CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_BIG_ENDIAN>;
    thumb32be.bits = 16;
    RDAssembler_Register(pm, &thumb32be);
}

void rdplugin_free(RDContext* ctx)
{
    for(const auto& [h, item] : CS_ITEMS)
    {
        auto* capstone = reinterpret_cast<Capstone*>(RDContext_GetUserData(ctx, item.first));
        if(capstone) delete capstone;
    }
}
