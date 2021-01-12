#pragma once

// Reference: https://0x04.net/~mwk/doc/xtensa.pdf

/* Binutils:
 * - https://github.com/bminor/binutils-gdb/blob/master/opcodes/xtensa-dis.c
 * - https://github.com/bminor/binutils-gdb/blob/master/bfd/xtensa-modules.c
 */

#include <rdapi/rdapi.h>
#include <functional>
#include <list>

struct XtensaInstruction;

template<Swap32_Callback Swap>
class Xtensa
{
    private:
        typedef std::function<void(RDContext*, RDEmulateResult*, const XtensaInstruction*)> EmulateCallback;
        struct XtensaInfo { rd_type theme; EmulateCallback cb; };

    public:
        Xtensa() = delete;
        static void initialize();
        static void emulate(RDContext* ctx, RDEmulateResult* result);
        static void render(RDContext* ctx, const RDRendererParams* rp);

    private:
        static void emulateJUMP(RDContext*, RDEmulateResult* result, const XtensaInstruction* xinstr);
        static void emulateBRANCH(RDContext*, RDEmulateResult* result, const XtensaInstruction* xinstr);
        static void emulateCALL(RDContext*, RDEmulateResult* result, const XtensaInstruction* xinstr);
        static void emulateRET(RDContext*, RDEmulateResult* result, const XtensaInstruction*);

    private:
        static std::unordered_map<std::string, XtensaInfo> m_info;
};
