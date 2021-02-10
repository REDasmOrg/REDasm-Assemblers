#include "mips_lifter.h"
#include "mips_registers.h"

void MIPSLifter::lift(RDILFunction* il, const MIPSDecodedInstruction* decoded, rd_address address)
{
    switch(decoded->opcode->id)
    {
        case MIPSMacro_Nop: RDILFunction_Append(il, RDILFunction_NOP(il)); break;

        case MIPSMacro_Li: {
            auto* copy = RDILFunction_COPY(il, RDILFunction_REG(il, sizeof(u32), MIPSDecoder::reg(decoded->instruction.i_u.rt)),
                                               RDILFunction_CNST(il, sizeof(u32), decoded->instruction.i_u.immediate));

            RDILFunction_Append(il, copy); break;
            break;
        }

        case MIPSInstruction_Jr: {
            RDILExpression* e = nullptr;
            if(decoded->instruction.r.rs == MIPSRegister_RA) e = RDILFunction_RET(il, RDILFunction_REG(il, sizeof(u32), MIPSDecoder::reg(decoded->instruction.r.rs)));
            else e = RDILFunction_GOTO(il, RDILFunction_REG(il, sizeof(u32), MIPSDecoder::reg(decoded->instruction.r.rs)));
            RDILFunction_Append(il, e);
            break;
        }

        case MIPSInstruction_Jal: {
            RDILExpression* call = nullptr;
            auto baddress = MIPSDecoder::calcAddress(decoded, address);
            if(baddress) call = RDILFunction_CALL(il, RDILFunction_CNST(il, sizeof(u32), *baddress));
            else call = RDILFunction_CALL(il, RDILFunction_UNKNOWN(il));
            RDILFunction_Append(il, call);
            break;
        }

        case MIPSInstruction_J: {
            RDILExpression* g = nullptr;
            auto baddress = MIPSDecoder::calcAddress(decoded, address);
            if(baddress) g = RDILFunction_GOTO(il, RDILFunction_CNST(il, sizeof(u32), *baddress));
            else g = RDILFunction_GOTO(il, RDILFunction_UNKNOWN(il));
            RDILFunction_Append(il, g);
            break;
        }

        default:
            RDILFunction_Append(il, RDILFunction_UNKNOWN(il));
            break;
    }
}
