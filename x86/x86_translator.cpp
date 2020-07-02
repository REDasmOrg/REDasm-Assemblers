#include "x86_translator.h"
#include <Zydis/Zydis.h>
#include <climits>

void X86Translator::rdil(const RDAssemblerPlugin* plugin, const RDInstruction* instruction, RDInstruction** rdil)
{
    switch(instruction->id) {
        case ZYDIS_MNEMONIC_PUSH:
            RDIL_EmitSUB(*rdil);
            RDIL_SetRegister(*rdil, 0, ZYDIS_REGISTER_ESP);
            RDIL_SetRegister(*rdil, 1, ZYDIS_REGISTER_ESP);
            RDIL_SetValue(*rdil, 2, plugin->bits / CHAR_BIT);
            RDIL_ADVANCE(rdil);

            RDIL_EmitSTORE(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            RDIL_SetRegister(*rdil, 1, ZYDIS_REGISTER_ESP);
            break;

        case ZYDIS_MNEMONIC_MOV:
            RDIL_EmitCOPY(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            RDIL_SetOperand(*rdil, 1, &instruction->operands[1]);
            break;

        case ZYDIS_MNEMONIC_CMP:
            RDIL_EmitSUB(*rdil);
            RDIL_SetILRegister(*rdil, 0, RDILRegister_Cond);
            RDIL_SetOperand(*rdil, 1, &instruction->operands[1]);
            RDIL_SetOperand(*rdil, 2, &instruction->operands[0]);
            break;

        case ZYDIS_MNEMONIC_JMP:
            RDIL_EmitJMP(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            break;

        case ZYDIS_MNEMONIC_JNZ:
            RDIL_EmitJMPNZ(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            break;

        case ZYDIS_MNEMONIC_JZ:
            RDIL_EmitJMPZ(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            break;

        case ZYDIS_MNEMONIC_CALL:
            RDIL_EmitCALL(*rdil);
            RDIL_SetOperand(*rdil, 0, &instruction->operands[0]);
            break;

        case ZYDIS_MNEMONIC_LEAVE:
            RDIL_EmitCOPY(*rdil);
            RDIL_SetRegister(*rdil, 0, ZYDIS_REGISTER_ESP);
            RDIL_SetRegister(*rdil, 1, ZYDIS_REGISTER_EBP);

            RDIL_ADVANCE(rdil);
            RDIL_EmitADD(*rdil);
            RDIL_SetRegister(*rdil, 0, ZYDIS_REGISTER_ESP);
            RDIL_SetRegister(*rdil, 1, ZYDIS_REGISTER_ESP);
            RDIL_SetValue(*rdil, 2, plugin->bits / CHAR_BIT);
            break;

        case ZYDIS_MNEMONIC_RET:
            if(instruction->operands[0].u_value) {
                RDIL_EmitADD(*rdil);
                RDIL_SetRegister(*rdil, 0, ZYDIS_REGISTER_ESP);
                RDIL_SetRegister(*rdil, 1, ZYDIS_REGISTER_ESP);
                RDIL_SetOperand(*rdil, 2, &instruction->operands[0]);
                RDIL_ADVANCE(rdil);
            }

            RDIL_EmitRET(*rdil);
            RDIL_SetRegister(*rdil, 0, ZYDIS_REGISTER_EAX);
            break;

        default: break;
    }
}
