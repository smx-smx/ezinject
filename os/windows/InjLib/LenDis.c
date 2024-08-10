/*********************************************************************************************
 * Length Disassembler                                                                       *
 *                                                                                           *
 * Disassembles Intel/AMD x86 instructions and returns their length.                         *
 *  - up to Intel P6, AMD Athlon                                                             *
 *  - includes MMX, SSE, SSE2, SS3, 3DNow!                                                   *
 *  - undocumented: AAD imm8, AAM imm8, FCMOV, FCOMI, ICEBP, LOADALL, RDPMC, SALC, UD2, UMOV *
 *                                                                                           *
 * (c) A. Miguel Feijao, 17/3/2005                                                           *
 *********************************************************************************************/

#include <windows.h>
#include "LenDis.h"

#define SIZE16               0          // 16-bit Operand/Address
#define SIZE32               1          // 32-bit Operand/Address

#define RETFOUND             1          // Warning: RET found
#define JMPFOUND             2          // Warning: JMP found
#define CALLFOUND            4          // Warning: CALL found
#define ABSADDRFOUND         8          // Warning: Absolute addressing found

#define BYTE1                0x000000   // 1 byte opcode
#define BYTE2                0x000001   // 2 byte opcode
#define WORD8                0x000001   // opcode + byte (port, ...)
#define IMM8                 0x000001   // opcode + imm8
#define PREFIX               0x000002   // prefix opcode
#define OPSIZE               0x000004   // opcode 0x66 (operand size)
#define ADDRSIZE             0x000008   // opcode 0x67 (address size)
#define OPCODE0F             0x000010   // opcode 0x0F
#define WORD16               0x000020   // opcode + word16 (16-bit displacement, ...)
#define IMM1632              0x000040   // immediate data (16/32 bits)
#define ADDR1632             0x000080   // displacement (16/32 bits)
#define MODRM                0x000100   // mod r/m (+ sib) byte
#define FPOINT               0x000100   // Floting-point instructions
#define INT                  0x000200   // INT n (check special case of INT 0x20)
#define JMP8                 0x000400   // JMP disp8 (0-7F: forward, 80-FF: backward)
#define JMPOFFSET            0x000800   // JMP full offset (16/32 bits)
#define CALLOFFSET           0x001000   // CALL full offset (16/32 bits)
#define JMPOFFSEL            0x002000   // JMP Offset(16/32) + Selector(16)
#define CALLOFFSEL           0x004000   // CALL Offset(16/32) + Selector(16)
#define OPCODEF6             0x008000   // opcode 0xF6
#define OPCODEF7             0x010000   // opcode 0xF7
#define OPCODEFF             0x020000   // opcode 0xFF
#define RET                  0x040000   // RET/RETF
#define OPCODEAE             0x080000   // opcode 0x0F,0xAE
#define OPCODE0F0F           0x100000   // opcode 0x0F,0x0F

const DWORD OpcodeTable[256] = {
            MODRM,              // 00 - ADD r/m,r8
            MODRM,              // 01 - ADD r/m,r16/32
            MODRM,              // 02 - ADD r8,r/m
            MODRM,              // 03 - ADD r16/32,r/m
            IMM8,               // 04 - ADD AL,imm8
            IMM1632,            // 05 - ADD (E)AX,imm16/32
            BYTE1,              // 06 - PUSH ES
            BYTE1,              // 07 - POP ES
            MODRM,              // 08 - OR r/m,r8
            MODRM,              // 09 - OR r/m,r16/32
            MODRM,              // 0A - OR r8,r/m
            MODRM,              // 0B - OR r16/32,r/m
            IMM8,               // 0C - OR AL,imm8
            IMM1632,            // 0D - OR (E)AX,imm16/32
            BYTE1,              // 0E - PUSH CS
            OPCODE0F,           // 0F - (opcode 0F)
                                //      POP CS
            MODRM,              // 10 - ADC r/m,r8
            MODRM,              // 11 - ADC r/m,r16/32
            MODRM,              // 12 - ADC r8,r/m
            MODRM,              // 13 - ADC r16/32,r/m
            IMM8,               // 14 - ADC AL,imm8
            IMM1632,            // 15 - ADC (E)AX,imm16/32
            BYTE1,              // 16 - PUSH SS
            BYTE1,              // 17 - POP SS
            MODRM,              // 18 - SBB r/m,r8
            MODRM,              // 19 - SBB r/m,r16/32
            MODRM,              // 1A - SBB r8,r/m
            MODRM,              // 1B - SBB r16/32,r/m
            IMM8,               // 1C - SBB AL,imm8
            IMM1632,            // 1D - SBB (E)AX,imm16/32
            BYTE1,              // 1E - PUSH DS
            BYTE1,              // 1F - POP DS
            MODRM,              // 20 - AND r/m,r8
            MODRM,              // 21 - AND r/m,r16/32
            MODRM,              // 22 - AND r8,r/m
            MODRM,              // 23 - AND r16/32,r/m
            IMM8,               // 24 - AND AL,imm8
            IMM1632,            // 25 - AND (E)AX,imm16/32
            PREFIX,             // 26 - ES:
            BYTE1,              // 27 - DAA
            MODRM,              // 28 - SUB r/m,r8
            MODRM,              // 29 - SUB r/m,r16/32
            MODRM,              // 2A - SUB r8,r/m
            MODRM,              // 2B - SUB r16/32,r/m
            IMM8,               // 2C - SUB AL,imm8
            IMM1632,            // 2D - SUB (E)AX,imm16/32
            PREFIX,             // 2E - CS:
            BYTE1,              // 2F - DAS
            MODRM,              // 30 - XOR r/m,r8
            MODRM,              // 31 - XOR r/m,r16/32
            MODRM,              // 32 - XOR r8, r/m
            MODRM,              // 33 - XOR r16/32,r/m
            IMM8,               // 34 - XOR AL,imm8
            IMM1632,            // 35 - XOR (E)AX,imm16/32
            PREFIX,             // 36 - SS:
            BYTE1,              // 37 - AAA
            MODRM,              // 38 - CMP r/m,r8
            MODRM,              // 39 - CMP r/m,r16/32
            MODRM,              // 3A - CMP r8,r/m
            MODRM,              // 3B - CMP r16/32,r/m
            IMM8,               // 3C - CMP AL,imm8
            IMM1632,            // 3D - CMP (E)AX,imm16/32
            PREFIX,             // 3E - DS:
            BYTE1,              // 3F - AAS
            BYTE1,              // 40 - INC (E)AX
            BYTE1,              // 41 - INC (E)CX
            BYTE1,              // 42 - INC (E)DX
            BYTE1,              // 43 - INC (E)BX
            BYTE1,              // 44 - INC (E)SP
            BYTE1,              // 45 - INC (E)BP
            BYTE1,              // 46 - INC (E)SI
            BYTE1,              // 47 - INC (E)DI
            BYTE1,              // 48 - DEC (E)AX
            BYTE1,              // 49 - DEC (E)CX
            BYTE1,              // 4A - DEC (E)DX
            BYTE1,              // 4B - DEC (E)BX
            BYTE1,              // 4C - DEC (E)SP
            BYTE1,              // 4D - DEC (E)BP
            BYTE1,              // 4E - DEC (E)SI
            BYTE1,              // 4F - DEC (E)DI
            BYTE1,              // 50 - PUSH (E)AX
            BYTE1,              // 51 - PUSH (E)CX
            BYTE1,              // 52 - PUSH (E)DX
            BYTE1,              // 53 - PUSH (E)BX
            BYTE1,              // 54 - PUSH (E)SP
            BYTE1,              // 55 - PUSH (E)BP
            BYTE1,              // 56 - PUSH (E)SI
            BYTE1,              // 57 - PUSH (E)DI
            BYTE1,              // 58 - POP (E)AX
            BYTE1,              // 59 - POP (E)CX
            BYTE1,              // 5A - POP (E)DX
            BYTE1,              // 5B - POP (E)BX
            BYTE1,              // 5C - POP (E)SP
            BYTE1,              // 5D - POP (E)BP
            BYTE1,              // 5E - POP (E)SI
            BYTE1,              // 5F - POP (E)DI
            BYTE1,              // 60 - PUSHA/PUSHAW/PUSHAD
            BYTE1,              // 61 - POPA/POPAW/POPAD
            MODRM,              // 62 - BOUND r16/32,mem
            MODRM,              // 63 - ARPL r/m,r16
            PREFIX,             // 64 - FS:
            PREFIX,             // 65 - GS:
            OPSIZE + PREFIX,    // 66 - (operand size)
                                //      (SSE/SSE2/SSE3 prefix)
            ADDRSIZE + PREFIX,  // 67 - (address size)
            IMM1632,            // 68 - PUSH imm16/32
            MODRM + IMM1632,    // 69 - IMUL reg,imm16/32
                                //      IMUL reg,r/m,imm16/32
            IMM8,               // 6A - PUSH imm8
            MODRM + IMM8,       // 6B - IMUL reg,imm8
                                //      IMUL reg,r/m,imm8
            BYTE1,              // 6C - INS(B)
            BYTE1,              // 6D - INSW/INSWD
            BYTE1,              // 6E - OUTS(B)
            BYTE1,              // 6F - OUTSW/OUTSD
            JMP8,               // 70 - JO disp8
            JMP8,               // 71 - JNO disp8
            JMP8,               // 72 - JB/JC/JNAE disp8
            JMP8,               // 73 - JAE/JNB/JNC disp8
            JMP8,               // 74 - JE/JZ disp8
            JMP8,               // 75 - JNE/JNZ disp8
            JMP8,               // 76 - JBE/JNA disp8
            JMP8,               // 77 - JA/JNBE disp8
            JMP8,               // 78 - JS disp8
            JMP8,               // 79 - JNS disp8
            JMP8,               // 7A - JP/JPE disp8
            JMP8,               // 7B - JNP/JPO disp8
            JMP8,               // 7C - JL/JNGE disp8
            JMP8,               // 7D - JGE/JNL disp8
            JMP8,               // 7E - JLE/JNG disp8
            JMP8,               // 7F - JG/JNLE disp8
            MODRM + IMM8,       // 80 - ADC/ADD/AND/CMP/OR/SBB/SUB/XOR r/m,imm8
            MODRM + IMM1632,    // 81 - ADC/ADD/AND/CMP/OR/SBB/SUB/XOR r/m,imm16/32
            MODRM + IMM8,       // 82 - ADC/ADD/AND/CMP/OR/SBB/SUB/XOR r/m,imm8
            MODRM + IMM8,       // 83 - ADC/ADD/AND/CMP/OR/SBB/SUB/XOR r/m,imm8
            MODRM,              // 84 - TEST r/m,r8
            MODRM,              // 85 - TEST r/m,r16/32
            MODRM,              // 86 - XCHG r8/rm,r/m/ r8
            MODRM,              // 87 - XCHG r1632/ r/m,r/m/ r1632
            MODRM,              // 88 - MOV r/m,r8
            MODRM,              // 89 - MOV r/m,r16/32
            MODRM,              // 8A - MOV r8,r/m
            MODRM,              // 8B - MOV r16/32,r/m
            MODRM,              // 8C - MOV r/m,sreg
            MODRM,              // 8D - LEA reg,mem
            MODRM,              // 8E - MOV sreg,r/m
            MODRM,              // 8F - POP r/m
            BYTE1,              // 90 - NOP
                                //      PAUSE (F3,90)
            BYTE1,              // 91 - XCHG (E)AX/(E)CX
            BYTE1,              // 92 - XCHG (E)AX/(E)DX
            BYTE1,              // 93 - XCHG (E)AX/(E)BX
            BYTE1,              // 94 - XCHG (E)AX/(E)SP
            BYTE1,              // 95 - XCHG (E)AX/(E)BP
            BYTE1,              // 96 - XCHG (E)AX/(E)SI
            BYTE1,              // 97 - XCHG (E)AX/(E)DI
            BYTE1,              // 98 - CBW/CWDE
            BYTE1,              // 99 - CWD/CDQ
            CALLOFFSEL,         // 9A - CALL sel:offset16/32
            BYTE1,              // 9B - (F)WAIT
            BYTE1,              // 9C - PUSHF/PUSHFW/PUSHFD
            BYTE1,              // 9D - POPF/POPFW/POPFD
            BYTE1,              // 9E - SAHF
            BYTE1,              // 9F - LAHF
            ADDR1632,           // A0 - MOV AL,mem
            ADDR1632,           // A1 - MOV (E)AX,mem
            ADDR1632,           // A2 - MOV mem,r8
            ADDR1632,           // A3 - MOV mem,(E)AX
            BYTE1,              // A4 - MOVS(B)
            BYTE1,              // A5 - MOVSW/MOVSD
            BYTE1,              // A6 - CMPS(B)
            BYTE1,              // A7 - CMPSW/CMPSD
            IMM8,               // A8 - TEST AL,imm8
            IMM1632,            // A9 - TEST (E)AX,imm16/32
            BYTE1,              // AA - STOS(B)
            BYTE1,              // AB - STOSW/STOSD
            BYTE1,              // AC - LODS(B)
            BYTE1,              // AD - LODSW/LODSD
            BYTE1,              // AE - SCAS(B)
            BYTE1,              // AF - SCASW/SCASD
            IMM8,               // B0 - MOV r8,imm8
            IMM8,               // B1 - MOV CL,imm8
            IMM8,               // B2 - MOV DL,imm8
            IMM8,               // B3 - MOV BL,imm8
            IMM8,               // B4 - MOV AH,imm8
            IMM8,               // B5 - MOV CH,imm8
            IMM8,               // B6 - MOV DH,imm8
            IMM8,               // B7 - MOV BH,imm8
            IMM1632,            // B8 - MOV reg,imm16/32
            IMM1632,            // B9 - MOV (E)CX,imm16/32
            IMM1632,            // BA - MOV (E)DX,imm16/32
            IMM1632,            // BB - MOV (E)BX,imm16/32
            IMM1632,            // BC - MOV (E)SP,imm16/32
            IMM1632,            // BD - MOV (E)BP,imm16/32
            IMM1632,            // BE - MOV (E)SI,imm16/32
            IMM1632,            // BF - MOV (E)DI,imm16/32
            MODRM + IMM8,       // C0 - RCL/ROL/ROR/SAL/SAR/SHL/SHR r/m,imm8
            MODRM + IMM8,       // C1 - RCL/ROL/ROR/SAL/SAR/SHL/SHR r/m,imm8
            WORD16 + RET,       // C2 - RET word16
            BYTE1 + RET,        // C3 - RET
            MODRM,              // C4 - LES r16/32,mem
            MODRM,              // C5 - LDS r16/32,mem
            MODRM + IMM8,       // C6 - MOV r/m,imm8
            MODRM + IMM1632,    // C7 - MOV r/m,imm16/32
            WORD16 + WORD8,     // C8 - ENTER word16,word8
            BYTE1,              // C9 - LEAVE
            WORD16 + RET,       // CA - RETF word16
            BYTE1 + RET,        // CB - RETF
            BYTE1,              // CC - INT 3
            INT,                // CD - INT n
            BYTE1,              // CE - INTO
            BYTE1 + RET,        // CF - IRET(D)
            MODRM,              // D0 - ROL/ROR/RCL/RCR/SAL/SAR/SHL/SHR r/m,1
            MODRM,              // D1 - ROL/ROR/RCL/RCR/SAL/SAR/SHL/SHR r/m,1
            MODRM,              // D2 - ROL/ROR/RCL/RCR/SAL/SAR/SHL/SHR r/m,CL
            MODRM,              // D3 - ROL/ROR/RCL/RCR/SAL/SAR/SHL/SHR r/m,CL
            BYTE2,              // D4 - AAM imm8
            BYTE2,              // D5 - AAD imm8
            BYTE1,              // D6 - SALC
            BYTE1,              // D7 - XLAT(B)
            FPOINT,             // D8 - (Floting-point instructions)
            FPOINT,             // D9 - (Floting-point instructions)
            FPOINT,             // DA - (Floting-point instructions)
            FPOINT,             // DB - (Floting-point instructions)
            FPOINT,             // DC - (Floting-point instructions)
            FPOINT,             // DD - (Floting-point instructions)
            FPOINT,             // DE - (Floting-point instructions)
            FPOINT,             // DF - (Floting-point instructions)
            JMP8,               // E0 - LOOPNZ/LOOPNE disp8
            JMP8,               // E1 - LOOPZ/LOOPE disp8
            JMP8,               // E2 - LOOP disp8
            JMP8,               // E3 - JCXZ/JECXZ disp8
            WORD8,              // E4 - IN AL,port
            WORD8,              // E5 - IN (E)AX,port
            WORD8,              // E6 - OUT port,AL
            WORD8,              // E7 - OUT port,(E)AX
            CALLOFFSET,         // E8 - CALL offset16/32
            JMPOFFSET,          // E9 - JMP offset16/32
            JMPOFFSEL,          // EA - JMP sel:offset16/32
            JMP8,               // EB - JMP disp8
            BYTE1,              // EC - IN AL,DX
            BYTE1,              // ED - IN (E)AX,DX
            BYTE1,              // EE - OUT DX,AL
            BYTE1,              // EF - OUT DX,(E)AX
            PREFIX,             // F0 - LOCK
            BYTE1,              // F1 - ICEBP
                                //      SMI
            PREFIX,             // F2 - REPNE
                                //      (SSE/SSE2/SSE3 prefix)
            PREFIX,             // F3 - REP(E)
                                //      (SSE/SSE2/SSE3 prefix)
            BYTE1,              // F4 - HLT
            BYTE1,              // F5 - CMC
            OPCODEF6,           // F6 - TEST/DIV/IDIV/MUL/IMUL/NEG/NOT imm8/r/m8
            OPCODEF7,           // F7 - TEST/DIV/IDIV/MUL/IMUL/NEG/NOT imm1632/r/m
            BYTE1,              // F8 - CLC
            BYTE1,              // F9 - STC
            BYTE1,              // FA - CLI
            BYTE1,              // FB - STI
            BYTE1,              // FC - CLD
            BYTE1,              // FD - STD
            MODRM,              // FE - INC/DEC r/m
            OPCODEFF            // FF - CALL/JMP/DEC/INC/PUSH r/m
            };

const DWORD Opcode0FTable[256] = {
            MODRM,              // 00 - LLDT/LTR/SLDT/STR/VERR/VERW r/m
            MODRM,              // 01 - INVLPG/LGDT/LIDT/LMSW/SGDT/SIDT/SMSW r/m
                                //      MONITOR (0F,01,C8)
                                //      MWAIT (0F,01,C9)
            MODRM,              // 02 - LAR reg,r/m
            MODRM,              // 03 - LSL reg,r/m
            0,                  // 04 -
            BYTE1,              // 05 - LOADALL286/SYSCALL
            BYTE1,              // 06 - CLTS
            BYTE1,              // 07 - LOADALL/SYSRET
            BYTE1,              // 08 - INVD
            BYTE1,              // 09 - WBINVD
            0,                  // 0A -
            BYTE1,              // 0B - UD2
            0,                  // 0C -
            MODRM,              // 0D - PREFETCH/PREFETCHW mem
            BYTE1,              // 0E - FEMMS
            OPCODE0F0F,         // 0F - Opcode 0F,0F (3DNOW! instructions)
            MODRM,              // 10 - MOVSS/MOVUPS/MOVSD/MOVUPD xmmreg/mem,xmmreg/mem
                                //      UMOV r/m,reg8
            MODRM,              // 11 - MOVSS/MOVUPS/MOVSD/MOVUPD xmmreg/mem,xmmreg/mem
                                //      UMOV r/m,reg
            MODRM,              // 12 - MOVHLPS/MOVLPS/MOVLPD xmmreg,xmmreg/mem
                                //      MOVDDUP/MOVSLDUP xmmreg,xmmreg/mem
                                //      UMOV reg8,r/m
            MODRM,              // 13 - MOVLPS/MOVLPD mem,xmmreg
                                //      UMOV reg,r/m
            MODRM,              // 14 - UNPCKLPS/UNPCKLPD xmmreg,xmmreg/mem
            MODRM,              // 15 - UNPCKHPS/UNPCKHPD xmmreg,xmmreg/mem
            MODRM,              // 16 - MOVHPS/MOVLHPS/MOVHPD/MOVSHDUP xmmreg,xmmreg/mem
            MODRM,              // 17 - MOVHPS/MOVHPD mem,xmmreg
            MODRM,              // 18 - PREFETCHNTA/PREFETCHT0/PREFETCHT1/PREFETCHT2 mem
            0,                  // 19 -
            0,                  // 1A -
            0,                  // 1B -
            0,                  // 1C -
            0,                  // 1D -
            0,                  // 1E -
            0,                  // 1F -
            BYTE2,              // 20 - MOV reg,CR0-4
            BYTE2,              // 21 - MOV reg,DR0-7
            BYTE2,              // 22 - MOV CR0-4,reg
            BYTE2,              // 23 - MOV DR0-7,reg
            BYTE2,              // 24 - MOV reg,TR3-7
            0,                  // 25 -
            BYTE2,              // 26 - MOV TR3-7,reg
            0,                  // 27 -
            MODRM,              // 28 - MOVAPS/MOVAPD xmmreg/mem,xmmreg/mem
            MODRM,              // 29 - MOVAPS/MOVAPD xmmreg/mem,xmmreg/mem
            MODRM,              // 2A - CVTPI2PS/CVTSI2SS/CVTPI2PD/CVTSI2SD xmmreg,r/m
            MODRM,              // 2B - MOVNTPS/MOVNTPD mem,xmmreg
            MODRM,              // 2C - CVTTPS2PI/CVTTSS2SI/CVTTPD2PI/CVTTSD2SI xmmreg/r32,xmmreg/mem
            MODRM,              // 2D - CVTPS2PI/CVTSS2SI/CVTPD2PI/CVTSD2SI xmmreg/r32,xmmreg/mem
            MODRM,              // 2E - UCOMISS/UCOMISD xmmreg,xmmreg/mem
            MODRM,              // 2F - COMISS/COMISD xmmreg,xmmreg/mem
            BYTE1,              // 30 - WRMSR
            BYTE1,              // 31 - RDTSC
            BYTE1,              // 32 - RDMSR
            BYTE1,              // 33 - RDPMC
            BYTE1,              // 34 - SYSENTER
            BYTE1,              // 35 - SYSEXIT
            MODRM,              // 36 - RDSHR r/m
            MODRM,              // 37 - WRSHR r/m
            BYTE1,              // 38 - SMINT
            0,                  // 39 -
            0,                  // 3A -
            0,                  // 3B -
            0,                  // 3C -
            0,                  // 3D -
            0,                  // 3E -
            0,                  // 3F -
            MODRM,              // 40 - CMOVO reg,reg/mem
            MODRM,              // 41 - CMOVNO reg,reg/mem
            MODRM,              // 42 - CMOVB/CMOVNE reg,reg/mem
            MODRM,              // 43 - CMOVAE/CMOVNB reg,reg/mem
            MODRM,              // 44 - CMOVE/CMOVZ reg,reg/mem
            MODRM,              // 45 - CMOVNE/CMOVNZ reg,reg/mem
            MODRM,              // 46 - CMOVBE/CMOVNA reg,reg/mem
            MODRM,              // 47 - CMOVA/CMOVNBE reg,reg/mem
            MODRM,              // 48 - CMOVS reg,reg/mem
            MODRM,              // 49 - CMOVNS reg,reg/mem
            MODRM,              // 4A - CMOVP/CMOVPE reg,reg/mem
            MODRM,              // 4B - CMOVNP/CMOVPO reg,reg/mem
            MODRM,              // 4C - CMOVL/CMOVNGE reg,reg/mem
            MODRM,              // 4D - CMOVGE/CMOVNL reg,reg/mem
            MODRM,              // 4E - CMOVLE/CMOVNG reg,reg/mem
            MODRM,              // 4F - CMOVG/CMOVNLE reg,reg/mem
            MODRM,              // 50 - MOVMSKPS/MOVMSKPD r32,xmmreg
                                //      PAVEB mmxreg,r/m
            MODRM,              // 51 - SQRTPS/SQRTSS/SQRTPD/SQRTSD xmmreg,xmmreg/mem
                                //      PADDSIW mmxreg,r/m
            MODRM,              // 52 - RSQRTPS/RSQRTSS xmmreg,xmmreg/mem
                                //      PMAGW mmreg,mmreg/mem
            MODRM,              // 53 - RCPPS/RCPSS xmmreg,xmmreg/mem
            MODRM,              // 54 - ANDPS/ANDPD xmmreg,xmmreg/mem
                                //      PDISTIB mmreg,mem
            MODRM,              // 55 - ANDNPS/ANDNPD xmmreg,xmmreg/mem
                                //      PSUBSIW mmreg,mmreg/mem
            MODRM,              // 56 - ORPS/ORPD xmmreg,xmmreg/mem
            MODRM,              // 57 - XORPS/XORPD xmmreg,xmmreg/mem
            MODRM,              // 58 - ADDPS/ADDSS/ADDPD/ADDSD xmmreg,xmmreg/mem
                                //      PMVZB mmxreg,mem
            MODRM,              // 59 - MULPS/MULSS/MULPD/MULSD xmmreg,xmmreg/mem
                                //      PMULHRWC mmreg,mmreg/mem
            MODRM,              // 5A - CVTPD2PS/CVTPS2PD/CVTSD2SS/CVTSS2SD xmmreg,xmmreg/mem
                                //      PMVNZB mmxreg,mem
            MODRM,              // 5B - CVTPS2DQ/CVTTPS2DQ/CVTDQ2PS xmmreg,xmmreg/mem
                                //      PMVLZB mmxreg,mem
            MODRM,              // 5C - SUBPS/SUBSS/SUBPD/SUBSD xmmreg,xmmreg/mem
                                //      PMVGEZB mmxreg,mem
            MODRM,              // 5D - MINPS/MINSS/MINPD/MINSD xmmreg,xmmreg/mem
                                //      PMULHRIW mmreg,mmreg/mem
            MODRM,              // 5E - DIVPS/DIVSS/DIVPD/DIVSD xmmreg,xmmreg/mem
                                //      PMACHRIW mmreg,mem
            MODRM,              // 5F - MAXPS/MAXSS/MAXPD/MAXSD xmmreg,xmmreg/mem
            MODRM,              // 60 - PUNPCKLBW mmxreg,mmxreg/mem
                                //      PUNPCKLBW xmmreg,xmmreg/mem
            MODRM,              // 61 - PUNPCKLWD mmxreg,mmxreg/mem
                                //      PUNPCKLWD xmmreg,xmmreg/mem
            MODRM,              // 62 - PUNPCKLDQ mmxreg,mmxreg/mem
                                //      PUNPCKLDQ xmmreg,xmmreg/mem
            MODRM,              // 63 - PACKSSWB mmxreg,mmxreg/mem
                                //      PACKSSWB xmmreg,xmmreg/mem
            MODRM,              // 64 - PCMPGTB mmxreg,mmxreg/mem
                                //      PCMPGTB xmmreg,xmmreg/mem
            MODRM,              // 65 - PCMPGTW mmxreg,mmxreg/mem
                                //      PCMPGTW xmmreg,xmmreg/mem
            MODRM,              // 66 - PCMPGTD mmxreg,mmxreg/mem
                                //      PCMPGTD xmmreg,xmmreg/mem
            MODRM,              // 67 - PACKUSWD mmxreg,mmxreg/mem
                                //      PACKUSWD xmmreg,xmmreg/mem
            MODRM,              // 68 - PUNPCKHBW mmxreg,mmxreg/mem
                                //      PUNPCKHBW xmmreg,xmmreg/mem
            MODRM,              // 69 - PUNPCKHWD mmxreg,mmxreg/mem
                                //      PUNPCKHWD xmmreg,xmmreg/mem
            MODRM,              // 6A - PUNPCKHDQ mmxreg,mmxreg/mem
                                //      PUNPCKHDQ xmmreg,xmmreg/mem
            MODRM,              // 6B - PACKSSDW mmxreg,mmxreg/mem
                                //      PACKSSDW xmmreg,xmmreg/mem
            MODRM,              // 6C - PUNPCKLQDQ xmmreg,xmmreg/mem
            MODRM,              // 6D - PUNPCKHQDQ xmmreg,xmmreg/mem
            MODRM,              // 6E - MOVD mmxreg,r/m
                                //      MOVD xmmreg,r/m
            MODRM,              // 6F - MOVQ mmxreg,mmxreg/mem
                                //      MOVDQA/MOVDQU xmmreg,xmmreg/mem
            MODRM + IMM8,       // 70 - PSHUFW mmreg,mmreg/mem,imm8
                                //      PSHUFLW/PSHUFHW/PSHUFD xmmreg,xmmreg/mem,imm8
            MODRM + IMM8,       // 71 - PSLLW/PSRAW/PSRLW mmxreg,imm8
                                //      PSLLW/PSRAW/PSRLW xmmreg,imm8
            MODRM + IMM8,       // 72 - PSLLD/PSRAD/PSRLD mmxreg,imm8
                                //      PSLLD/PSRAD/PSRLD xmmreg,imm8
            MODRM + IMM8,       // 73 - PSSLQ/PSRLQ mmxreg,imm8
                                //      PSLLDQ/PSSLQ/PSRLDQ/PSRLQ xmmreg,imm8
            MODRM,              // 74 - PCMPEQB mmxreg,mmxreg/mem
                                //      PCMPEQB xmmreg,xmmreg/mem
            MODRM,              // 75 - PCMPEQW mmxreg,mmxreg/mem
                                //      PCMPEQW xmmreg,xmmreg/mem
            MODRM,              // 76 - PCMPEQD mmxreg,mmxreg/mem
                                //      PCMPEQD xmmreg,xmmreg/mem
            BYTE1,              // 77 - EMMS
            MODRM,              // 78 - SVDC mem,segreg
            MODRM,              // 79 - RSDC segreg,mem
            MODRM,              // 7A - SVLDT mem
            MODRM,              // 7B - RSLDT mem
            MODRM,              // 7C - HADDPD/HADDPS xmmreg,xmmreg/mem
                                //      SVTS mem
            MODRM,              // 7D - HSUBPD/HSUBPS xmmreg,xmmreg/mem
                                //      RSTS mem
            MODRM,              // 7E - MOVD r/m,mmxreg
                                //      MOVD/MOVQ r/m/xmmreg,xmmreg/mem
                                //      SMINTOLD
            MODRM,              // 7F - MOVQ mmxreg/mem,mmxreg
                                //      MOVDQA/MOVDQU xmmreg/mem,xmmreg
            JMPOFFSET,          // 80 - JO offset16/32
            JMPOFFSET,          // 81 - JNO offset16/32
            JMPOFFSET,          // 82 - JB offset16/32
            JMPOFFSET,          // 83 - JAE offset16/32
            JMPOFFSET,          // 84 - JE offset16/32
            JMPOFFSET,          // 85 - JNE offset16/32
            JMPOFFSET,          // 86 - JBE offset16/32
            JMPOFFSET,          // 87 - JA offset16/32
            JMPOFFSET,          // 88 - JS offset16/32
            JMPOFFSET,          // 89 - JNS offset16/32
            JMPOFFSET,          // 8A - JP offset16/32
            JMPOFFSET,          // 8B - JNP offset16/32
            JMPOFFSET,          // 8C - JL offset16/32
            JMPOFFSET,          // 8D - JGE offset16/32
            JMPOFFSET,          // 8E - JLE offset16/32
            JMPOFFSET,          // 8F - JG offset16/32
            MODRM,              // 90 - SETO r/m
            MODRM,              // 91 - SETNO r/m
            MODRM,              // 92 - SETB r/m
            MODRM,              // 93 - SETAE r/m
            MODRM,              // 94 - SETE r/m
            MODRM,              // 95 - SETNE r/m
            MODRM,              // 96 - SETBE r/m
            MODRM,              // 97 - SETA r/m
            MODRM,              // 98 - SETS r/m
            MODRM,              // 99 - SETNS r/m
            MODRM,              // 9A - SETP r/m
            MODRM,              // 9B - SETNP r/m
            MODRM,              // 9C - SETL r/m
            MODRM,              // 9D - SETGE r/m
            MODRM,              // 9E - SETLE r/m
            MODRM,              // 9F - SETG r/m
            BYTE1,              // A0 - PUSH FS
            BYTE1,              // A1 - POP FS
            BYTE1,              // A2 - CPUID
            MODRM,              // A3 - BT mem,r16/32
            MODRM + IMM8,       // A4 - SHLD r/m,reg,imm8
            MODRM,              // A5 - SHLD r/m,reg,CL
            MODRM,              // A6 - CMPXCHG486 r/m,r8
                                //      XBTS reg,r/m
            MODRM,              // A7 - CMPXCHG486 r/m,r16/32
                                //      IBTS r/m,r16/32
            BYTE1,              // A8 - PUSH GS
            BYTE1,              // A9 - POP GS
            BYTE1,              // AA - RSM
            MODRM,              // AB - BTS mem,r16/32
            MODRM + IMM8,       // AC - SHRD r/m,reg,imm8
            MODRM,              // AD - SHRD r/m,reg,CL
            OPCODEAE,           // AE - FXRSTOR/FXSAVE/LDMXCSR/STMXCSR/CLFLUSH mem
                                //      SFENCE/LFENCE/MFENCE
            MODRM,              // AF - IMUL reg,r/m
            MODRM,              // B0 - CMPXCHG r/m,r8
            MODRM,              // B1 - CMPXCHG r/m,r16/32
            MODRM,              // B2 - LDS reg,mem
            MODRM,              // B3 - BTR mem,r16/32
            MODRM,              // B4 - LFS reg,mem
            MODRM,              // B5 - LGS reg,mem
            MODRM,              // B6 - MOVZX reg,r/m8
            MODRM,              // B7 - MOVZX reg,r/m16
            0,                  // B8 -
            BYTE1,              // B9 - UD1
            MODRM + IMM8,       // BA - BT/BTC/BTR/BTS reg,imm8
            MODRM,              // BB - BTC mem,r16/32
            MODRM,              // BC - BSF r16/32,mem
            MODRM,              // BD - BSR r16/32,mem
            MODRM,              // BE - MOVSX reg,r/m8
            MODRM,              // BF - MOVSX reg,r/m16
            MODRM,              // C0 - XADD r/m,r8
            MODRM,              // C1 - XADD r/m,r16/32
            MODRM + IMM8,       // C2 - CMPxxPS/CMPxxSS/CMPxxPD/CMPxxSD xmmreg,xmmreg/mem
                                //      (xx=EQ,LT,LE,UNORD,NE,NLT,NLE,ORD)
            MODRM,              // C3 - MOVNTI mem,r32
            MODRM + IMM8,       // C4 - PINSRW mmreg,reg32/m16,imm8
                                //      PINSRW xmmreg,reg32/m16,imm8
            MODRM + IMM8,       // C5 - PEXTRW reg32,mmreg,imm8
                                //      PEXTRW reg32,xmmreg,imm8
            MODRM + IMM8,       // C6 - SHUFPS/SHUFPD xmmreg,xmmreg/mem,imm8
            MODRM,              // C7 - CMPXCHG8B mem
            BYTE1,              // C8 - BSWAP (E)AX
            BYTE1,              // C9 - BSWAP (E)CX
            BYTE1,              // CA - BSWAP (E)DX
            BYTE1,              // CB - BSWAP (E)BX
            BYTE1,              // CC - BSWAP (E)SP
            BYTE1,              // CD - BSWAP (E)BP
            BYTE1,              // CE - BSWAP (E)SI
            BYTE1,              // CF - BSWAP (E)DI
            MODRM,              // D0 - ADDSUBPD/ADDSUBPS xmmreg,xmmreg/mem
            MODRM,              // D1 - PSRLW mmxreg,mmxreg/mem
                                //      PSRLW xmmreg,xmmreg/mem
            MODRM,              // D2 - PSRLD mmxreg,mmxreg/mem
                                //      PSRLD xmmreg,xmmreg/mem
            MODRM,              // D3 - PSRLQ mmxreg,mmxreg/mem
                                //      PSRLQ xmmreg,xmmreg/mem
            MODRM,              // D4 - PADDQ mmreg/xmmreg,mmreg/mem/xmmreg
            MODRM,              // D5 - PMULLW mmxreg,mmxreg/mem
                                //      PMULLW xmmreg,xmmreg/mem
            MODRM,              // D6 - MOVQ2DQ/MOVDQ2Q/MOVQ xmmreg/mmreg/mem,mmreg/xmmreg
            MODRM,              // D7 - PMOVMSKB reg32,mmreg
                                //      PMOVMSKB reg32,xmmreg
            MODRM,              // D8 - PSUBUSB mmxreg/mem,mmxreg
                                //      PSUBUSB xmmreg/mem,xmmreg
            MODRM,              // D9 - PSUBUSW mmxreg/mem,mmxreg
                                //      PSUBUSW xmmreg/mem,xmmreg
            MODRM,              // DA - PMINUB mmreg,mmreg/mem
                                //      PMINUB xmmreg,xmmreg/mem
            MODRM,              // DB - PAND mmxreg,mmxreg/mem
                                //      PAND xmmreg,xmmreg/mem
            MODRM,              // DC - PADDUSB mmxreg,mmxreg/mem
                                //      PADDUSB xmmreg,xmmreg/mem
            MODRM,              // DD - PADDUSW mmxreg,mmxreg/mem
                                //      PADDUSW xmmreg,xmmreg/mem
            MODRM,              // DE - PMAXUB mmreg,mmreg/mem
                                //      PMAXUB xmmreg,xmmreg/mem
            MODRM,              // DF - PANDN mmxreg,mmxreg/mem
                                //      PANDN xmmreg,xmmreg/mem
            MODRM,              // E0 - PAVGB mmreg,mmreg/mem
                                //      PAVGB xmmreg,xmmreg/mem
            MODRM,              // E1 - PSRAW mmxreg,mmxreg/mem
                                //      PSRAW xmmreg,xmmreg/mem
            MODRM,              // E2 - PSRAD mmxreg,mmxreg/mem
                                //      PSRAD xmmreg,xmmreg/mem
            MODRM,              // E3 - PAVGW mmreg,mmreg/mem
                                //      PAVGW xmmreg,xmmreg/mem
            MODRM,              // E4 - PMULHUW mmxreg,mmxreg/mem
                                //      PMULHUW xmmreg,xmmreg/mem
            MODRM,              // E5 - PMULHW mmxreg,mmxreg/mem
                                //      PMULHW xmmreg,xmmreg/mem
            MODRM,              // E6 - CVTPD2DQ/CVTTPD2DQ/CVTDQ2PD xmmreg,xmmreg/mem
            MODRM,              // E7 - MOVNTQ mem,mmreg/mem
                                //      MOVBTDQ mem,xmmreg
            MODRM,              // E8 - PSUBSB mmxreg/mem,mmxreg
                                //      PSUBSB xmmreg/mem,xmmreg
            MODRM,              // E9 - PSUBSW mmxreg/mem,mmxreg
                                //      PSUBSW xmmreg/mem,xmmreg
            MODRM,              // EA - PMINSW mmreg,mmreg/mem
                                //      PMINSW xmmreg,xmmreg/mem
            MODRM,              // EB - POR mmxreg,mmxreg/mem
                                //      POR xmmreg,xmmreg/mem
            MODRM,              // EC - PADDSB mmxreg,mmxreg/mem
                                //      PADDSB xmmreg,xmmreg/mem
            MODRM,              // ED - PADDSW mmxreg,mmxreg/mem
                                //      PADDSW xmmreg,xmmreg/mem
            MODRM,              // EE - PMAXSW mmreg,mmreg/mem
                                //      PMAXSW xmmreg,xmmreg/mem
            MODRM,              // EF - PXOR mmxreg,mmxreg/mem
                                //      PXOR xmmreg,xmmreg/mem
            MODRM,              // F0 - LDDQU xmm,m128
            MODRM,              // F1 - PSLLW mmxreg,mmxreg/mem
                                //      PSLLW xmmreg,xmmreg/mem
            MODRM,              // F2 - PSLLD mmxreg,mmxreg/mem
                                //      PSLLD xmmreg,xmmreg/mem
            MODRM,              // F3 - PSLLQ mmxreg,mmxreg/mem
                                //      PSLLQ xmmreg,xmmreg/mem
            MODRM,              // F4 - PMULUDQ mmreg, mmreg/mem
                                //      PMULUDQ xmmreg, xmmreg/mem
            MODRM,              // F5 - PMADDWD mmxreg,mmxreg/mem
                                //      PMADDWD xmmreg,xmmreg/mem
            MODRM,              // F6 - PSADBW mmreg,mmreg/mem
                                //      PSADBW xmmreg,xmmreg/mem
            MODRM,              // F7 - MASKMOVQ mmreg,mmreg
                                //      MASKMOVDQU xmmreg,xmmreg
            MODRM,              // F8 - PSUBB mmxreg/mem,mmxreg
                                //      PSUBB xmmreg/mem,xmmreg
            MODRM,              // F9 - PSUBW mmxreg/mem,mmxreg
                                //      PSUBW xmmreg/mem,xmmreg
            MODRM,              // FA - PSUBD mmxreg/mem,mmxreg
                                //      PSUBD xmmreg/mem,xmmreg
            MODRM,              // FB - PSUBQ mmxreg/mem,mmxreg
                                //      PSUBQ mmreg,mmreg/mem
                                //      PSUBQ mem/xmmreg,xmmreg/mem
            MODRM,              // FC - PADDB mmxreg,mmxreg/mem
                                //      PADDB xmmreg,xmmreg/mem
            MODRM,              // FD - PADDW mmxreg,mmxreg/mem
                                //      PADDW xmmreg,xmmreg/mem
            MODRM,              // FE - PADDD mmxreg,mmxreg/mem
                                //      PADDD xmmreg,xmmreg/mem
            BYTE1,              // FF - UD0
            };
/*
const DWORD Opcode0F0FTable[256] = {
            0,                  // 00 -
            0,                  // 01 -
            0,                  // 02 -
            0,                  // 03 -
            0,                  // 04 -
            0,                  // 05 -
            0,                  // 06 -
            0,                  // 07 -
            0,                  // 08 -
            0,                  // 09 -
            0,                  // 0A -
            0,                  // 0B -
            MODRM,              // 0C - PI2FW mreg,mreg/mem
            MODRM,              // 0D - PI2FD mreg,mreg/mem
            0,                  // 0E -
            0,                  // 0F -
            0,                  // 10 -
            0,                  // 11 -
            0,                  // 12 -
            0,                  // 13 -
            0,                  // 14 -
            0,                  // 15 -
            0,                  // 16 -
            0,                  // 17 -
            0,                  // 18 -
            0,                  // 19 -
            0,                  // 1A -
            0,                  // 1B -
            MODRM,              // 1C - PF2IW mreg,mreg/mem
            MODRM,              // 1D - PF2ID mreg,mreg/mem
            0,                  // 1E -
            0,                  // 1F -
            0,                  // 20 -
            0,                  // 21 -
            0,                  // 22 -
            0,                  // 23 -
            0,                  // 24 -
            0,                  // 25 -
            0,                  // 26 -
            0,                  // 27 -
            0,                  // 28 -
            0,                  // 29 -
            0,                  // 2A -
            0,                  // 2B -
            0,                  // 2C -
            0,                  // 2D -
            0,                  // 2E -
            0,                  // 2F -
            0,                  // 30 -
            0,                  // 31 -
            0,                  // 32 -
            0,                  // 33 -
            0,                  // 34 -
            0,                  // 35 -
            0,                  // 36 -
            0,                  // 37 -
            0,                  // 38 -
            0,                  // 39 -
            0,                  // 3A -
            0,                  // 3B -
            0,                  // 3C -
            0,                  // 3D -
            0,                  // 3E -
            0,                  // 3F -
            0,                  // 40 -
            0,                  // 41 -
            0,                  // 42 -
            0,                  // 43 -
            0,                  // 44 -
            0,                  // 45 -
            0,                  // 46 -
            0,                  // 47 -
            0,                  // 48 -
            0,                  // 49 -
            0,                  // 4A -
            0,                  // 4B -
            0,                  // 4C -
            0,                  // 4D -
            0,                  // 4E -
            0,                  // 4F -
            0,                  // 50 -
            0,                  // 51 -
            0,                  // 52 -
            0,                  // 53 -
            0,                  // 54 -
            0,                  // 55 -
            0,                  // 56 -
            0,                  // 57 -
            0,                  // 58 -
            0,                  // 59 -
            0,                  // 5A -
            0,                  // 5B -
            0,                  // 5C -
            0,                  // 5D -
            0,                  // 5E -
            0,                  // 5F -
            0,                  // 60 -
            0,                  // 61 -
            0,                  // 62 -
            0,                  // 63 -
            0,                  // 64 -
            0,                  // 65 -
            0,                  // 66 -
            0,                  // 67 -
            0,                  // 68 -
            0,                  // 69 -
            0,                  // 6A -
            0,                  // 6B -
            0,                  // 6C -
            0,                  // 6D -
            0,                  // 6E -
            0,                  // 6F -
            0,                  // 70 -
            0,                  // 71 -
            0,                  // 72 -
            0,                  // 73 -
            0,                  // 74 -
            0,                  // 75 -
            0,                  // 76 -
            0,                  // 77 -
            0,                  // 78 -
            0,                  // 79 -
            0,                  // 7A -
            0,                  // 7B -
            0,                  // 7C -
            0,                  // 7D -
            0,                  // 7E -
            0,                  // 7F -
            0,                  // 80 -
            0,                  // 81 -
            0,                  // 82 -
            0,                  // 83 -
            0,                  // 84 -
            0,                  // 85 -
            0,                  // 86 -
            0,                  // 87 -
            0,                  // 88 -
            0,                  // 89 -
            MODRM,              // 8A - PFNACC mreg,mreg/mem
            0,                  // 8B -
            0,                  // 8C -
            0,                  // 8D -
            MODRM,              // 8E - PFPNACC mreg,mreg/mem
            0,                  // 8F -
            0,                  // 90 - PFCMPGE mreg,mreg/mem
            0,                  // 91 -
            0,                  // 92 -
            0,                  // 93 -
            MODRM,              // 94 - PFMIN mreg,mreg/mem
            0,                  // 95 -
            MODRM,              // 96 - PFRCP mreg,mreg/mem
            MODRM,              // 97 - PFRSQRT mreg,mreg/mem
            0,                  // 98 -
            0,                  // 99 -
            MODRM,              // 9A - PFSUB mreg,mreg/mem
            0,                  // 9B -
            0,                  // 9C -
            0,                  // 9D -
            MODRM,              // 9E - PFADD mreg,mreg/mem
            0,                  // 9F -
            MODRM,              // A0 - PFCMPGT mreg,mreg/mem
            0,                  // A1 -
            0,                  // A2 -
            0,                  // A3 -
            MODRM,              // A4 - PFMAX mreg,mreg/mem
            0,                  // A5 -
            MODRM,              // A6 - PFRCPIT1 mreg,mreg/mem
            MODRM,              // A7 - PFRSQIT1 mreg,mreg/mem
            0,                  // A8 -
            0,                  // A9 -
            MODRM,              // AA - PFSUBR mreg,mreg/mem
            0,                  // AB -
            0,                  // AC -
            0,                  // AD -
            MODRM,              // AE - PFACC mreg,mreg/mem
            0,                  // AF -
            MODRM,              // B0 - PFCMPEQ mreg,mreg/mem
            0,                  // B1 -
            0,                  // B2 -
            0,                  // B3 -
            MODRM,              // B4 - PFMUL mreg,mreg/mem
            0,                  // B5 -
            MODRM,              // B6 - PFRCPIT2 mreg,mreg/mem
            MODRM,              // B7 - PMULHRW mreg,mreg/mem
            0,                  // B8 -
            0,                  // B9 -
            0,                  // BA -
            MODRM,              // BB - PSWAPD mreg,mreg/mem
            0,                  // BC -
            0,                  // BD -
            0,                  // BE -
            MODRM,              // BF - PAVGUSB mreg,mreg/mem
            0,                  // C0 -
            0,                  // C1 -
            0,                  // C2 -
            0,                  // C3 -
            0,                  // C4 -
            0,                  // C5 -
            0,                  // C6 -
            0,                  // C7 -
            0,                  // C8 -
            0,                  // C9 -
            0,                  // CA -
            0,                  // CB -
            0,                  // CC -
            0,                  // CD -
            0,                  // CE -
            0,                  // CF -
            0,                  // D0 -
            0,                  // D1 -
            0,                  // D2 -
            0,                  // D3 -
            0,                  // D4 -
            0,                  // D5 -
            0,                  // D6 -
            0,                  // D7 -
            0,                  // D8 -
            0,                  // D9 -
            0,                  // DA -
            0,                  // DB -
            0,                  // DC -
            0,                  // DD -
            0,                  // DE -
            0,                  // DF -
            0,                  // E0 -
            0,                  // E1 -
            0,                  // E2 -
            0,                  // E3 -
            0,                  // E4 -
            0,                  // E5 -
            0,                  // E6 -
            0,                  // E7 -
            0,                  // E8 -
            0,                  // E9 -
            0,                  // EA -
            0,                  // EB -
            0,                  // EC -
            0,                  // ED -
            0,                  // EE -
            0,                  // EF -
            0,                  // F0 -
            0,                  // F1 -
            0,                  // F2 -
            0,                  // F3 -
            0,                  // F4 -
            0,                  // F5 -
            0,                  // F6 -
            0,                  // F7 -
            0,                  // F8 -
            0,                  // F9 -
            0,                  // FA -
            0,                  // FB -
            0,                  // FC -
            0,                  // FD -
            0,                  // FE -
            0                   // FF -
            };
*/

/**********************************************************************
 * Return the length of the instruction pointed by pCode.             *
 * If the instruction is a JMP return the jump displacement.          *
 * If the instruction is a RET/JMP/CALL/ABSADDR return it in nResult. *
 **********************************************************************/
int LengthDisassembler(PBYTE pCode, int *nResult, int *Displacement)
{
    BYTE    b;
    DWORD   f;
    int     nBytes;
    int     OpSize = SIZE32;    // Default operand size = 32 bits
    int     AddrSize = SIZE32;  // Default address size = 32 bits
    int     Size;
    BYTE    bModRm, mod, rm, sib;
	static  int OSWin9x = 0;
    OSVERSIONINFO   osvi;

    *Displacement = 0;
    *nResult = 0;
    nBytes = 0;

	if (OSWin9x == 0)
	{
		// Get Windows version
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		if (!GetVersionEx(&osvi))
			OSWin9x = -1;
		else
		{
			if (osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
				OSWin9x = 1;
			else
				OSWin9x = -1;
		}
	}

Repeat:
    b = *pCode++;       // Get opcode
    f = OpcodeTable[b]; // Lookup opcode in table

Compare:
    // 0F prefix
    if (f & OPCODE0F)
    {
        nBytes++;
        b = *pCode++;           // Get opcode
        f = Opcode0FTable[b];   // Lookup opcode in 0F table
    }

    // 0F,0F prefix
    if (f & OPCODE0F0F)
        {
        nBytes++;              // Add 3DNow! suffix
        f |= MODRM;
        }

    // Switch operand size
    if (f & OPSIZE)
    {
        OpSize = (OpSize == SIZE32 ? SIZE16 : SIZE32);
    }

    // Switch address size
    if (f & ADDRSIZE)
    {
        AddrSize = (AddrSize == SIZE32 ? SIZE16 : SIZE32);
    }

    // RET
    if (f & RET)
        *nResult = *nResult | RETFOUND;

    // Opcode is a prefix
    if (f & PREFIX)
    {
        nBytes++;
        goto Repeat;
    }

    // 2-byte opcode
    if (f & BYTE2 /* || f & WORD8 */)
    {
        nBytes++;
    }

    // Opcode + word16
    if (f & WORD16)
    {
        nBytes += 2;
    }

    // INT x
    if (f & INT)
    {
        b = *pCode++;
        nBytes++;

        // INT 0x20 (VxDCall on Win9x)
        if (b == 0x20 && OSWin9x == 1)
            nBytes += 4; // INT 0x20 is followed by service # (WORD) and Device ID (WORD)
    }

    // JMP displ8
    if (f & JMP8)
    {
        *nResult |= JMPFOUND;
        *Displacement = *(signed char *)pCode;
        nBytes++;
    }

    // JMP offset16/32
    if (f & JMPOFFSET)
    {
        *nResult |= JMPFOUND;
        Size = (OpSize == SIZE16 ? 2 : 4); // imm16 or imm32
        *Displacement = Size == 2 ? *(signed short *)pCode : *(signed long *)pCode;
        nBytes += Size;
    }

    // CALL offset16/32
    if (f & CALLOFFSET)
    {
        *nResult |= CALLFOUND;
        Size = (OpSize == SIZE16 ? 2 : 4); // imm16 or imm32
        nBytes += Size;
    }

    // JMP selector(16 bits):offset(16/32 bits)
    if (f & JMPOFFSEL)
        nBytes += (OpSize == SIZE16 ? 4 : 6); // offset16 or offset32

    // CALL selector(16 bits):offset(16/32 bits)
    if (f & CALLOFFSEL)
        nBytes += (OpSize == SIZE16 ? 4 : 6); // offset16 or offset32

    // Displacement (16/32 bits)
    if (f & ADDR1632)
    {
        *nResult |= ABSADDRFOUND;
        nBytes += (AddrSize == SIZE16 ? 2 : 4); // disp16 or disp32
    }

    // Immediate data (16/32 bits)
    if (f & IMM1632)
    {
        nBytes += (OpSize == SIZE16 ? 2 : 4); // imm16 or imm32
    }

    // Opcode 0F,AE
    if (f & OPCODEAE)
    {
        b = *pCode;
        if ((b == 0xF8) || // SFENCE (0F,AE,F8)
            (b == 0xE8) || // LFENCE (0F,AE,E8)
            (b == 0x70))   // MFENCE (0F,AE,70)
            nBytes++;
        else
            f |= MODRM; // FXSTOR/...
    }

    // Opcode F6
    if (f & OPCODEF6)
    {
        bModRm = *pCode;

        if ((bModRm & 0x38) == 0x00)    // bits 543 = 000 => TEST reg, imm8
            f = MODRM + IMM8;
        else
            f = MODRM;                  // DIV/...

        goto Compare;
    }

    // Opcode F7
    if (f & OPCODEF7)
    {
        bModRm = *pCode;

        if ((bModRm & 0x38) == 0x00)    // bits 543 = 000 => TEST reg, imm16/32
            f = MODRM + IMM1632;
        else
            f = MODRM;                  // DIV/...

        goto Compare;
    }

    // Opcode FF
    if (f & OPCODEFF)
    {
        bModRm = *pCode;

        if (bModRm & 0x18){}			// CALL
        else if (bModRm & 0x28){}		// JMP
        f = MODRM;

        goto Compare;
    }

    // Mod r/m (+ sib)
    if (f & MODRM)
    {
        bModRm = *pCode++;
        nBytes++;   // Add ModR/m byte

        // Extract mod and r/m
        mod = (bModRm & 0xC0) >> 6;    // mod = bits 6,7
        rm = bModRm & 0x07;            // r/m = bits 0,1,2

        if (mod == 3)                  // mod = 11 => register
        {
            ;                          // do nothing
        }
        else if (AddrSize == SIZE16)   // 16 bits
        {
            if (mod == 0)               // mod = 00
            {
                if (rm == 6)            // rm = 110
                {
                    *nResult |= ABSADDRFOUND;
                    nBytes += 2;        // d16
                }
            }
            else if (mod == 1)          // mod = 01
                nBytes++;               // d8
            else if (mod == 2)          // mod = 10
                nBytes += 2;            // d16           [AbsAddr + reg]
        }
        else                            // 32 bits
        {
            if (rm == 4 && mod != 3)    // sib
            {
                sib = *pCode++;
                nBytes++;               // Add sib byte

                if (mod == 0 && ((sib & 0x07) == 5))    // mod = 00, base = 101
                    nBytes += 4;        // d32          [AbsAddr + Reg]
            }

            if (mod == 0 && rm == 5)
            {
                *nResult |= ABSADDRFOUND;
                nBytes += 4;            // d32
            }
            else if (mod == 1)
                nBytes ++;              // d8
            else if (mod == 2)
                nBytes += 4;            // d32          [AbsAddr + Reg]
        }
    }

    // 1st opcode
    nBytes++;

    return nBytes;
}
