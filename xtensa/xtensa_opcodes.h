#pragma once

#include <redasm/redasm.h>

using namespace REDasm;

enum class XtensaOpcodeFormat
{
    None, NNone,
    RRR, RRR_2r, RRR_2rr, RRR_2imm, RRR_extui, RRR_1imm, RRR_immr, RRR_sext, RRR_sll, RRR_slli, RRR_srai, RRR_sh, RRR_ssa, RRR_ssai,
    RRI8, RRI8_addmi, RRI8_b, RRI8_bb, RRI8_i12, RRI8_disp, RRI8_disp16, RRI8_disp32,
    RI16,
    RSR, RSR_spec,
    CALL, CALL_sh,
    CALLX,
    BRI8_imm, BRI8_immu,
    BRI12,
    RRRN, RRRN_disp, RRRN_addi, RRRN_2r,
    RI6, RI7,
    RI12S3,
};

union XTensaOpcodeBytes
{
    u32 opcode;

    struct {
        u8 b1, b2, b3, unused;
    };
};

struct XtensaInstructionDefinition
{
    size_t id;
    const char* mnemonic;
    u32 opcode, mask;
    XtensaOpcodeFormat format;
    InstructionType type;
    bool narrow;
};

namespace XtensaOpcodes {

enum {
    None,
    Abs, Add, Addi, Addmi, Addx2, Addx4, Addx8, And,
    Ball, Bany, Bbc, Bbs, Bbci, Bbsi, Beq, Beqi, Beqz, Bge, Bgei, Bgeu, Bgeui, Bgez, Blt, Blti, Bltu, Bltui, Bltz, Bnall, Bnone, Bne, Bnei, Bnez, Break,
    Call0, Call4, Call8, Call12, Callx0, Callx4, Callx8, Callx12,
    Dsync,
    Entry, Esync, Excw, Extui, Extw,
    Isync,
    J, Jx,
    L8ui, L16si, L16ui, L32i, L32r,
    Memw, Moveqz, Movgez, Movi, Movltz, Movnez, Mul16s, Mul16u, Mull, Muluh,
    Neg, Nsa, Nsau, Nop,
    Or,
    Ret, Retw_n, Rfe, Rfi, Rsil, Rsr_prid, Rsr_epc1, Rsr_epc2, Rsr_epc3, Rsr_epc4, Rsr_epc5, Rsr_epc6, Rsr_epc7, Rsr_ps, Rsr_exccause, Rsr_ccount, Rsr_excvaddr, Rsr_depc, Rsr_ccompare0, Rsr_interrupt, Rsr_intenable, Rsr_sar, Rsr_ddr, Rsr, Rsync,
    S8i, S16i, S32i, Sext, Sll, Slli, Sra, Srai, Src, Srl, Srli, Ssa8b, Ssa8l, Ssai, Ssl, Ssr, Sub, Subx2, Subx4, Subx8,
    Waiti, Wdtlb, Witlb, Wsr_intenable, Wsr_litbase, Wsr_vecbase, Wsr_ps, Wsr_epc1, Wsr_ccompare0, Wsr_intclear, Wsr_sar, Wsr,
    Xor, Xsr,
    Add_n, Addi_n,
    Beqz_n, Bnez_n,
    Mov_n,
    Break_n,
    Ret_n,
    L32i_n,
    Movi_n,
    Nop_n,
    S32i_n,
};

}

namespace Xtensa {

extern const XtensaInstructionDefinition definitions[];
extern const size_t definitionsCount;

} // namespace Xtensa
