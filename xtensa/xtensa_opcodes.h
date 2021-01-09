#pragma once

#include <rdapi/rdapi.h>

enum XtensaEncoding {
    XtensaEncoding_None, XtensaEncoding_NNone,

    XtensaEncoding_RRR, XtensaEncoding_RRR_2r, XtensaEncoding_RRR_2rr, XtensaEncoding_RRR_2imm, XtensaEncoding_RRR_extui, XtensaEncoding_RRR_1imm,
    XtensaEncoding_RRR_immr, XtensaEncoding_RRR_sext, XtensaEncoding_RRR_sll, XtensaEncoding_RRR_slli, XtensaEncoding_RRR_srai, XtensaEncoding_RRR_sh,
    XtensaEncoding_RRR_ssa, XtensaEncoding_RRR_ssai,

    XtensaEncoding_RRI8, XtensaEncoding_RRI8_addmi, XtensaEncoding_RRI8_b, XtensaEncoding_RRI8_bb, XtensaEncoding_RRI8_i12, XtensaEncoding_RRI8_disp,
    XtensaEncoding_RRI8_disp16, XtensaEncoding_RRI8_disp32,

    XtensaEncoding_RI16,
    XtensaEncoding_RSR, XtensaEncoding_RSR_spec,
    XtensaEncoding_CALL, XtensaEncoding_CALL_sh,
    XtensaEncoding_CALLX,
    XtensaEncoding_BRI8_imm, XtensaEncoding_BRI8_immu,
    XtensaEncoding_BRI12,
    XtensaEncoding_RRRN, XtensaEncoding_RRRN_disp, XtensaEncoding_RRRN_addi, XtensaEncoding_RRRN_2r,
    XtensaEncoding_RI6, XtensaEncoding_RI7,
    XtensaEncoding_RI12S3,
};

enum XtensaInstructionId {
    XtensaInstruction_None,

    XtensaInstruction_Abs, XtensaInstruction_Add, XtensaInstruction_Addi, XtensaInstruction_Addmi, XtensaInstruction_Addx2,
    XtensaInstruction_Addx4, XtensaInstruction_Addx8, XtensaInstruction_And,

    XtensaInstruction_Ball, XtensaInstruction_Bany, XtensaInstruction_Bbc, XtensaInstruction_Bbs, XtensaInstruction_Bbci,
    XtensaInstruction_Bbsi, XtensaInstruction_Beq, XtensaInstruction_Beqi, XtensaInstruction_Beqz, XtensaInstruction_Bge,
    XtensaInstruction_Bgei, XtensaInstruction_Bgeu, XtensaInstruction_Bgeui, XtensaInstruction_Bgez, XtensaInstruction_Blt,
    XtensaInstruction_Blti, XtensaInstruction_Bltu, XtensaInstruction_Bltui, XtensaInstruction_Bltz, XtensaInstruction_Bnall,
    XtensaInstruction_Bnone, XtensaInstruction_Bne, XtensaInstruction_Bnei, XtensaInstruction_Bnez, XtensaInstruction_Break,

    XtensaInstruction_Call0, XtensaInstruction_Call4, XtensaInstruction_Call8, XtensaInstruction_Call12, XtensaInstruction_Callx0,
    XtensaInstruction_Callx4, XtensaInstruction_Callx8, XtensaInstruction_Callx12,

    XtensaInstruction_Dsync,
    XtensaInstruction_Entry, XtensaInstruction_Esync, XtensaInstruction_Excw, XtensaInstruction_Extui, XtensaInstruction_Extw,
    XtensaInstruction_Isync, XtensaInstruction_Ill,
    XtensaInstruction_J, XtensaInstruction_Jx,
    XtensaInstruction_L8ui, XtensaInstruction_L16si, XtensaInstruction_L16ui, XtensaInstruction_L32i, XtensaInstruction_L32r,

    XtensaInstruction_Memw,

    XtensaInstruction_Moveqz, XtensaInstruction_Movgez, XtensaInstruction_Movi, XtensaInstruction_Movltz,
    XtensaInstruction_Movnez, XtensaInstruction_Mul16s, XtensaInstruction_Mul16u, XtensaInstruction_Mull, XtensaInstruction_Muluh,

    XtensaInstruction_Neg, XtensaInstruction_Nsa, XtensaInstruction_Nsau, XtensaInstruction_Nop,
    XtensaInstruction_Or,

    XtensaInstruction_Ret, XtensaInstruction_Retw_n, XtensaInstruction_Rfe, XtensaInstruction_Rfi, XtensaInstruction_Rsil, XtensaInstruction_Rsr_prid,
    XtensaInstruction_Rsr_epc1, XtensaInstruction_Rsr_epc2, XtensaInstruction_Rsr_epc3, XtensaInstruction_Rsr_epc4, XtensaInstruction_Rsr_epc5, XtensaInstruction_Rsr_epc6,
    XtensaInstruction_Rsr_epc7, XtensaInstruction_Rsr_ps, XtensaInstruction_Rsr_exccause, XtensaInstruction_Rsr_ccount, XtensaInstruction_Rsr_excvaddr, XtensaInstruction_Rsr_depc,
    XtensaInstruction_Rsr_ccompare0, XtensaInstruction_Rsr_interrupt, XtensaInstruction_Rsr_intenable, XtensaInstruction_Rsr_sar, XtensaInstruction_Rsr_ddr, XtensaInstruction_Rsr,
    XtensaInstruction_Rsync,

    XtensaInstruction_S8i, XtensaInstruction_S16i, XtensaInstruction_S32i, XtensaInstruction_Sext, XtensaInstruction_Sll, XtensaInstruction_Slli, XtensaInstruction_Sra,
    XtensaInstruction_Srai, XtensaInstruction_Src, XtensaInstruction_Srl, XtensaInstruction_Srli, XtensaInstruction_Ssa8b, XtensaInstruction_Ssa8l, XtensaInstruction_Ssai,
    XtensaInstruction_Ssl, XtensaInstruction_Ssr, XtensaInstruction_Sub, XtensaInstruction_Subx2, XtensaInstruction_Subx4, XtensaInstruction_Subx8,

    XtensaInstruction_Waiti, XtensaInstruction_Wdtlb, XtensaInstruction_Witlb, XtensaInstruction_Wsr_intenable, XtensaInstruction_Wsr_litbase, XtensaInstruction_Wsr_vecbase,
    XtensaInstruction_Wsr_ps, XtensaInstruction_Wsr_epc1, XtensaInstruction_Wsr_ccompare0, XtensaInstruction_Wsr_intclear, XtensaInstruction_Wsr_sar, XtensaInstruction_Wsr,

    XtensaInstruction_Xor, XtensaInstruction_Xsr,
    XtensaInstruction_Add_n, XtensaInstruction_Addi_n,
    XtensaInstruction_Beqz_n, XtensaInstruction_Bnez_n,

    XtensaInstruction_Mov_n,
    XtensaInstruction_Break_n,
    XtensaInstruction_Ret_n,
    XtensaInstruction_L32i_n,
    XtensaInstruction_Movi_n,
    XtensaInstruction_Nop_n,
    XtensaInstruction_S32i_n,
};

union XTensaOpcodeBytes
{
    u32 opcode;

    struct {
        u8 b1, b2, b3, unused;
    };
};

struct XtensaInstruction
{
    size_t id;
    const char* mnemonic;
    u32 opcode, mask;
    XtensaEncoding encoding;
    rd_type type;
    rd_flag flags;
    u32 size;
};

extern const XtensaInstruction Xtensa_Definitions[];
extern const size_t Xtensa_DefinitionsCount;
