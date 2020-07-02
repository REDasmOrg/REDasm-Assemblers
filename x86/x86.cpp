#include "x86.h"
#include "x86_translator.h"
#include <rdapi/rdapi.h>
#include <vector>

#define BUFFER_SIZE 256

X86Assembler::X86Assembler(const RDPluginHeader* plugin)
{
    m_plugin = reinterpret_cast<const RDAssemblerPlugin*>(plugin);

    if(m_plugin->bits == 32) ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
    else ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

void X86Assembler::emulate(RDDisassembler* disassembler, const RDInstruction* instruction)
{
    switch(instruction->type)
    {
        case InstructionType_Call:
            RDDisassembler_EnqueueAddress(disassembler, instruction, instruction->operands[0].u_value);
            break;

        case InstructionType_Jump:
            RDDisassembler_EnqueueAddress(disassembler, instruction, instruction->operands[0].u_value);
            if(HAS_FLAG(instruction, InstructionFlags_Conditional)) break;
            return;

        default:
            RDDisassembler_CheckOperands(disassembler, instruction);
            break;
    }

    if(!HAS_FLAG(instruction, InstructionFlags_Stop))
        RDDisassembler_EnqueueNext(disassembler, instruction);
}

bool X86Assembler::decode(RDBufferView* view, RDInstruction* instruction)
{
    ZydisDecodedInstruction zinstr;

    ZyanStatus s = ZydisDecoderDecodeBuffer(&m_decoder, RDBufferView_Data(view), static_cast<ZyanUSize>(RDBufferView_Size(view)), &zinstr);
    if(!ZYAN_SUCCESS(s)) return false;

    instruction->id = zinstr.mnemonic;
    instruction->size = zinstr.length;
    this->categorizeInstruction(instruction, &zinstr);
    this->writeMnemonic(instruction, &zinstr);
    this->writeOperands(instruction, &zinstr);
    return true;
}

bool X86Assembler::render(RDRenderItemParams* rip)
{
    if(!IS_TYPE(rip, RendererItemType_Operand)) return false;

    const RDOperand* op = rip->operand;

    if(IS_TYPE(op, OperandType_Displacement))
    {
        bool needsign = false;
        RDRendererItem_Push(rip->rendereritem, "[", nullptr, nullptr);

        if(op->base != RD_NREG)
        {
            RDRendererItem_Push(rip->rendereritem, ZydisRegisterGetString(static_cast<ZydisRegister>(op->base)), "register_fg", nullptr);
            needsign = true;
        }

        if(op->index != RD_NREG)
        {
            if(needsign) RDRendererItem_Push(rip->rendereritem, "+", nullptr, nullptr);
            RDRendererItem_Push(rip->rendereritem, ZydisRegisterGetString(static_cast<ZydisRegister>(op->index)), "register_fg", nullptr);

            if(op->scale > 1)
            {
                RDRendererItem_Push(rip->rendereritem, "*", nullptr, nullptr);
                RDRenderer_Immediate(rip, op->scale);
            }

            needsign = true;
        }

        if(op->displacement > 0)
        {
            if(needsign) RDRendererItem_Push(rip->rendereritem, "+", nullptr, nullptr);
            RDRenderer_Immediate(rip, op->displacement);
        }
        else
        {
            RDRendererItem_Push(rip->rendereritem, "-", nullptr, nullptr);
            RDRenderer_Immediate(rip, std::abs(op->displacement));
        }

        RDRendererItem_Push(rip->rendereritem, "]", nullptr, nullptr);
        return true;
    }

    return false;
}

void X86Assembler::categorizeInstruction(RDInstruction* instruction, const ZydisDecodedInstruction* zinstr) const
{
    switch(zinstr->meta.category)
    {
        case ZYDIS_CATEGORY_PUSH:      instruction->type = InstructionType_Push; break;
        case ZYDIS_CATEGORY_POP:       instruction->type = InstructionType_Pop;  break;
        case ZYDIS_CATEGORY_CALL:      instruction->type = InstructionType_Call; break;
        case ZYDIS_CATEGORY_UNCOND_BR: instruction->type = InstructionType_Jump; break;

        case ZYDIS_CATEGORY_RET:
            instruction->type = InstructionType_Ret;
            instruction->flags = InstructionFlags_Stop;
            break;

        case ZYDIS_CATEGORY_COND_BR:
            instruction->type = InstructionType_Jump;
            instruction->flags = InstructionFlags_Conditional;
            break;

        default: break;
    }
}

void X86Assembler::writeMnemonic(RDInstruction* instruction, const ZydisDecodedInstruction* zinstr) const
{
    std::vector<u8> buffer(BUFFER_SIZE);
    ZydisFormatterTokenConst* token = nullptr;
    std::string fullmnemonic;

    if(!ZYAN_SUCCESS(ZydisFormatterTokenizeInstruction(&m_formatter, zinstr, buffer.data(), buffer.size(), ZYDIS_RUNTIME_ADDRESS_NONE, &token)))
        return;

    ZydisTokenType tokentype;
    ZyanConstCharPointer tokenvalue = nullptr;

    while(token)
    {
        ZydisFormatterTokenGetValue(token, &tokentype, &tokenvalue);

        if(tokentype == ZYDIS_TOKEN_MNEMONIC)
        {
            if(!fullmnemonic.empty()) fullmnemonic += " ";
            fullmnemonic += tokenvalue;
        }
        else if(tokentype == ZYDIS_TOKEN_PREFIX) fullmnemonic += tokenvalue;

        if(!ZYAN_SUCCESS(ZydisFormatterTokenNext(&token))) token = nullptr;
    }

    RDInstruction_SetMnemonic(instruction, fullmnemonic.c_str());
}

void X86Assembler::writeOperands(RDInstruction* instruction, const ZydisDecodedInstruction* zinstr) const
{
    ZyanU64 calcaddress = 0;

    for(size_t i = 0; i < zinstr->operand_count; i++)
    {
        const ZydisDecodedOperand& zop = zinstr->operands[i];
        if(zop.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN) continue;

        RDOperand* op = nullptr;

        switch(zop.type)
        {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                op = RDInstruction_PushOperand(instruction, OperandType_Register);
                op->reg = zop.reg.value;
                break;

            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                op = RDInstruction_PushOperand(instruction, OperandType_Immediate);

                if(!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(zinstr, &zop, instruction->address, &calcaddress))) {
                   if(zop.imm.is_signed) op->s_value = zop.imm.value.s;
                   else op->u_value = zop.imm.value.u;
                }
                else op->u_value = calcaddress;

                break;

            case ZYDIS_OPERAND_TYPE_MEMORY:
                if(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(zinstr, &zop, instruction->address, &calcaddress))) {
                    op = RDInstruction_PushOperand(instruction, OperandType_Memory);
                    op->u_value = calcaddress;
                }
                else {
                    op = RDInstruction_PushOperand(instruction, OperandType_Displacement);
                    this->writeMemoryOperand(op, &zop);
                }
                break;

            default:
                rd_log("Operand " + std::to_string(zop.type) + " not implemented");
                continue;
        }
    }
}

void X86Assembler::writeMemoryOperand(RDOperand* operand, const ZydisDecodedOperand* zop) const
{
    operand->type = OperandType_Displacement;
    operand->scale = zop->mem.scale;

    if(zop->mem.base == ZYDIS_REGISTER_NONE) operand->base = RD_NREG;
    else operand->base = zop->mem.base;

    if(zop->mem.index == ZYDIS_REGISTER_NONE) operand->index = RD_NREG;
    else operand->index = zop->mem.index;

    if(zop->mem.disp.has_displacement)  operand->displacement = zop->mem.disp.value;

    if((operand->base == RD_NREG) && (operand->index == RD_NREG) && zop->mem.disp.has_displacement)
        operand->type = OperandType_Memory;
}

static void init(RDPluginHeader* plugin) { plugin->p_data = new X86Assembler(plugin); }
static void free(RDPluginHeader* plugin) { delete reinterpret_cast<X86Assembler*>(plugin->p_data); }

static bool decode(const RDAssemblerPlugin* plugin, RDBufferView* view, RDInstruction* instruction)
{
    return reinterpret_cast<X86Assembler*>(plugin->p_data)->decode(view, instruction);
}

static void emulate(const RDAssemblerPlugin* plugin, RDDisassembler* disassembler, const RDInstruction* instruction)
{
    reinterpret_cast<X86Assembler*>(plugin->p_data)->emulate(disassembler, instruction);
}

static bool render(const RDAssemblerPlugin* plugin, RDRenderItemParams* rip)
{
    return reinterpret_cast<X86Assembler*>(plugin->p_data)->render(rip);
}

static const char* regname(RDAssemblerPlugin*, const RDInstruction*, rd_register_id r) { return ZydisRegisterGetString(static_cast<ZydisRegister>(r)); }

void redasm_entry()
{
    RD_PLUGIN_CREATE(RDAssemblerPlugin, x86_32, "x86_32");
    x86_32.bits = 32;
    x86_32.init = &init;
    x86_32.free = &free;
    x86_32.regname = &regname;
    x86_32.decode = &decode;
    x86_32.emulate = &emulate;
    x86_32.render = &render;
    x86_32.rdil = &X86Translator::rdil;
    x86_32.regname = &regname;

    RD_PLUGIN_CREATE(RDAssemblerPlugin, x86_64, "x86_64");
    x86_64.bits = 64;
    x86_64.init = &init;
    x86_64.free = &free;
    x86_64.decode = &decode;
    x86_64.emulate = &emulate;
    x86_64.render = &render;
    x86_64.rdil = &X86Translator::rdil;
    x86_64.regname = &regname;

    RDAssembler_Register(&x86_32);
    RDAssembler_Register(&x86_64);
}
