#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "disassemble.h"
#include "utils.h"

static const char *sreg[] = {"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"};

static const char *decode_condition(int a)
{
	static const char *conditions[] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
    return conditions[a];
}

static const char *decode_shift(int a)
{
	static const char *shifts[] = {"lsl", "lsr", "asr", "ror"};
	return shifts[a];
}

static const char *decode_specifier(int a)
{
    if (a == 6)
        return "";

	static const char *specifiers[] = {"8b", "16b", "4h", "8h", "2s", "4s", NULL, "2d"};
	return specifiers[a];
}

static const char *decode_arrangement_specifier(int a)
{
    if ((a & 0b000011) == 0b000010)
        return "8b";
    else if ((a & 0b000011) == 0b000011)
        return "16b";
    else if ((a & 0b000111) == 0b000100)
        return "4h";
    else if ((a & 0b000111) == 0b000101)
        return "8h";
    else if ((a & 0b001111) == 0b001000)
        return "2s";
    else if ((a & 0b001111) == 0b001001)
        return "4s";
    else if ((a & 0b011111) == 0b010001)
        return "2d";

    return NULL;
}

static const char *decode_barrier(int a)
{
	switch (a)
	{
		case 0b1111: return "sy";
		case 0b1110: return "st";
		case 0b1101: return "ld";
		case 0b1011: return "ish";
		case 0b1010: return "ishst";
		case 0b1001: return "ishld";
		case 0b0111: return "nsh";
		case 0b0110: return "nshst";
		case 0b0101: return "nshld";
		case 0b0011: return "osh";
		case 0b0010: return "oshst";
		case 0b0001: return "oshld";
		default: return "";
	}
}

static const char *decode_pstate(int a)
{
	switch (a)
	{
		case 0b000101: return "spsel";
		case 0b011110: return "daifset";
		case 0b011111: return "daifclr";
		case 0b000011: return "uao";
		case 0b000100: return "pan";
		case 0b011001: return "ssbs";
		case 0b011010: return "dit";
		case 0b011100: return "tco";
		default: return "";
	}
}

static void decode_prefetch(int a, char *out)
{
	uint8_t target = masks(a, 0b11, 1);
	if (target == 0b11)
		goto no_decode;

	char type[4] = {0};
	switch (masks(a, 0b11, 3))
	{
		case 0b00: strcpy(type, "pld"); break;
		case 0b01: strcpy(type, "pli"); break;
		case 0b10: strcpy(type, "pst"); break;
		default: goto no_decode;
	}

	char policy[5] = {0};
	if (mask(a, 0b1))
		strcpy(policy, "strm");
	else
		strcpy(policy, "keep");

	snprintf(out, 24, "%sl%d%s", type, target + 1, policy);
	return;

	no_decode:
	snprintf(out, 24, "#0x%x", a);
}

static const char *decode_extend(int a)
{
    static const char *extends[] = {"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};
    return extends[a];
}

static const char *decode_reg_extend(int a)
{
    switch (a)
    {
        case 0b010: return "uxtw";
        case 0b011: return "lsl";
        case 0b110: return "sxtw";
        case 0b111: return "sxtx";
    }
    
    return NULL;
}

uint64_t bitfield_replicate(uint64_t mask, unsigned int e)
{
    while (e < 64)
    {
        mask |= mask << e;
        e *= 2;
    }

    return mask;
}

uint64_t bitmask64(unsigned int length)
{
    return ~0ULL >> (64 - length);
}

uint64_t ones(uint8_t len)
{
    return (((1ULL << ((len & 0x40) >> 1)) - 1) << 32) | ((1ULL << (len & 0x3f)) - 1);
}

uint64_t decode_bit_masks(bool N, int8_t imms, int8_t immr, uint8_t bits)
{
    // yoinked from https://github.com/Siguza/iometa/blob/master/src/a64.c

    uint8_t len = (N << 6) | (~imms & 0x3f);
    len = (len & (1 << 6)) ? 6 : (len & (1 << 5)) ? 5 : (len & (1 << 4)) ? 4 : (len & (1 << 3)) ? 3 : (len & (1 << 2)) ? 2 : (len & (1 << 1)) ? 1 : (len & (1 << 0)) ? 0 : -1;
    uint64_t levels = ones(len);
    uint64_t S = imms & levels;
    uint64_t R = immr & levels;
    uint8_t esize = 1 << len;
    uint64_t welem = ones(S + 1);
    uint64_t wmask = (welem >> R) | ((welem & ones(R % esize)) << (esize - (R % esize)));
    while(esize < bits)
    {
        wmask |= wmask << esize;
        esize <<= 1;
    }
    return wmask;
}

bool move_wide_preferred(bool sf, bool N, int8_t imms, int8_t immr)
{
    uint64_t x = decode_bit_masks(N, imms, immr, 32 << sf);

	if (sf == 0)
		x &= 0xffffffff;

	if (((x & 0xffffffffffff0000UL) == 0) || ((x & 0xffffffff0000ffffUL) == 0) || ((x & 0xffff0000ffffffffUL) == 0) || ((x & 0x0000ffffffffffffUL) == 0))
		return true;

	x = ~x;

	if (sf == 0)
		x &= 0xffffffff;

	if (((x & 0xffffffffffff0000UL) == 0) || ((x & 0xffffffff0000ffffUL) == 0) || ((x & 0xffff0000ffffffffUL) == 0) || ((x & 0x0000ffffffffffffUL) == 0))
		return true;

	return false;
}

bool bx_preferred(bool sf, bool u, int8_t imms, int8_t immr)
{
    if ((uint8_t)imms < (uint8_t)immr)
        return 0;

    if (((sf << 5) | 0b11111) == ~0)
        return 0;

    if (!immr)
    {
        if (!sf && (imms != 0b111 || imms != 0b1111))
            return 0;

        if (((sf << 1) | u) == 0b10 && (imms == 0b111 || imms == 0b1111 || imms == 0b11111))
            return 0;
    }

    return 1;
}

double build_float(uint8_t imm8, uint8_t bits)
{
    uint64_t a = masks(imm8, 0b1, 7);
    uint64_t B = !masks(imm8, 0b1, 6);
    uint64_t b = masks(imm8, 0b1, 6);
    uint64_t c = masks(imm8, 0b1, 5);
    uint64_t d = masks(imm8, 0b1, 4);
    uint64_t e = masks(imm8, 0b1, 3);
    uint64_t f = masks(imm8, 0b1, 2);
    uint64_t g = masks(imm8, 0b1, 1);
    uint64_t h = mask(imm8, 0b1);

    uint64_t ret = 0;

    switch (bits)
    {
        case 16:
        {
            ret = (a << 15) | (B << 14) | (b << 13) | (b << 12) | (c < 11) | (d << 10) | (e << 9) | (f << 8) | (g << 7) | (h << 6);
            break;
        }

        case 32:
        {
            ret = (a << 31) | (B << 30) | (b << 29) | (b << 28) | (b << 27) | (b << 26) | (b << 25) | (c << 24) | (d << 23) | (e << 22) | (f << 21) | (g << 20) | (h << 19);
            break;
        }

        case 64:
        {
            ret = (a << 63) | (B << 62) | (b << 61) | (b << 60) | (b << 59) | (b << 58) | (b << 57) | (b << 56) | (b << 55) | (b << 54) | (c << 53) | (d << 52) | (e << 51) | (f << 50) | (g << 49) | (h << 48);
            break;
        }
    }

    double *_f = (double *)&ret;
    return *_f;
}

char *imm(int64_t imm, decode_context_t *context, bool sign)
{
    static char immediate_buffers[4][32];
    static uint8_t index = 0;

    index &= 3;

    *immediate_buffers[index] = '\0';

    switch (context->integer_style)
    {
        case 0:
        {
            if (sign && imm < 0)
                snprintf(immediate_buffers[index], 32, "#-0x%" PRIx64, 0 - imm);
            else
                snprintf(immediate_buffers[index], 32, "#0x%" PRIx64, imm);

            break;
        }

        case 1:
        {
            const char *format = sign ? "#0x%" PRId64 : "#0x%" PRIu64;
            snprintf(immediate_buffers[index], 32, format, imm);
            break;
        }
    }
    
    return immediate_buffers[index++];
}

char *fimm(double fimm, decode_context_t *context)
{
    static char immediate_buffers[4][32];
    static uint8_t index = 0;

    index &= 3;

    *immediate_buffers[index] = '\0';

    switch (context->float_style)
    {
        case 0:
        {
            snprintf(immediate_buffers[index], 32, "#%f", fimm);
            break;
        }

        case 1:
        {
            snprintf(immediate_buffers[index], 32, "#%e", fimm);
            break;
        }

        case 2:
        {
            snprintf(immediate_buffers[index], 32, "#%g", fimm);
            break;
        }
    }

    return immediate_buffers[index++];
}

char *reg(uint8_t reg, bool possible_sp, uint8_t bits, bool simdfp)
{
    static char register_buffers[5][5];
    static uint8_t i = 0;

    i &= 3;

    *register_buffers[i] = '\0';

    char rc;

    if (simdfp)
    {
        switch (bits)
        {
            case 8: rc = 'b'; break;
            case 16: rc = 'h'; break;
            case 32: rc = 's'; break;
            case 64: rc = 'd'; break;
            case 128: rc = 'q'; break;
        }

        snprintf(register_buffers[i], 5, "%c%d", rc, reg);
    }
    else
    {
        rc = (bits == 64 || bits == 1) ? 'x' : 'w';

        if (reg == 31)
        {
            if (possible_sp)
                strcpy(register_buffers[i], rc == 'x' ? "sp" : "wsp");
            else
                snprintf(register_buffers[i], 5, "%czr", rc);
        }
        else
        {
            snprintf(register_buffers[i], 5, "%c%d", rc, reg);
        }
    }

    return register_buffers[i++];
}

char *symbol(uint64_t value, decode_context_t *context)
{
    symbol_data_t *symbol_data = context->symbol_data;

    if (symbol_data && symbol_data->symbols)
    {
        for (int i = 0; i < context->symbol_data->nsyms; i++)
        {
            symbol_t *symbol = context->symbol_data->symbols + i;

            if (symbol->offset == value)
                return symbol->name;
        }
    }
    
    static char symbol_buffers[2][32];
    static uint8_t index = 0;

    index &= 1;

    *symbol_buffers[index] = '\0';
    snprintf(symbol_buffers[index], 32, "loc_%" PRIx64, value);
    
    return symbol_buffers[index++];
}

int index_match(uint8_t thing, uint8_t *masks, uint8_t *matches, int count)
{
    for (int i = 0; i < count; i++)
    {
        if (mask(thing, masks[i]) == matches[i])
            return i;
    }

    return -1;
}

void disassemble_reserved(decode_context_t *context)
{
    uint32_t instruction = context->instruction;

    if (!masks(instruction, 0b1111111111111111, 16))
    {
        uint16_t imm16 = mask(instruction, 0b1111111111111111);
        snprintf(context->decode_string, 512, "udf %s", imm(imm16, context, 0));
    }
}

void disassemble_sve(decode_context_t *context)
{
    // still don't know what this is.
}

void disassemble_data_immediate(decode_context_t *context)
{
    uint32_t instruction = context->instruction;

    uint8_t op0 = masks(instruction, 0b111, 23);
    static uint8_t op0_mask[] = { 0b110, 0b111, 0b111, 0b111, 0b111, 0b111, 0b111};
    static uint8_t op0_id[] = { 0b000, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111};

    bool sf = masks(instruction, 0b1, 31);
    uint8_t rd = mask(instruction, 0b11111);
    uint8_t rn = masks(instruction, 0b11111, 5);

    int g = index_match(op0, op0_mask, op0_id, 7);

    if (g < 0)
        return;
    
    switch (g)
    {
        case 0:
        {
            uint8_t immlo = masks(instruction, 0b11, 29);
            uint32_t immhi = masks(instruction, 0b1111111111111111111, 5);
            int64_t adr = sign_extend((uint64_t)((immhi << 2) | immlo), 21);

            if (sf)
                snprintf(context->decode_string, 512, "adrp %s, %s", reg(rd, 0, 1, 0), symbol(context->pc - (context->pc & 0xFFF) + (adr * 4096), context));
            else
                snprintf(context->decode_string, 512, "adr %s, %s", reg(rd, 0, 1, 0), symbol(context->pc + adr, context));

            break;
        }

        case 1:
        {
            uint8_t op = masks(instruction, 0b11, 29);
            bool n = masks(instruction, 0b1, 30);
            bool sh = masks(instruction, 0b1, 22);
            uint16_t imm12 = masks(instruction, 0b111111111111, 10);

            static const char *instructions[] = { "add", "adds", "sub", "subs", "cmn", "cmp" };

            char add[16] = {0};
            if (sh)
                snprintf(add, 16, ", lsl %s", imm(12, context, 0));

            char *immediate = imm(imm12, context, 0);

            if (!op && !sh && !imm12 && (rd == 31 || rn == 31))
                snprintf(context->decode_string, 512, "mov %s, %s", reg(rd, 1, sf, 0), reg(rn, 1, sf, 0));
            else if ((op & 1) && rd == 31)
                snprintf(context->decode_string, 512, "%s %s, %s%s", instructions[4 + n], reg(rn, 1, sf, 0), immediate, add);
            else
                snprintf(context->decode_string, 512, "%s %s, %s, %s%s", instructions[op], reg(rd, 1, sf, 0), reg(rn, 1, sf, 0), immediate, add);

            break;
        }

        case 2:
        {
            // armv8.5

            bool op = masks(instruction, 0b1, 30);
            bool S = masks(instruction, 0b1, 29);

            uint8_t uimm6 = masks(instruction, 0b111111, 21);
            uint8_t op3 = masks(instruction, 0b11, 15);
            uint8_t uimm4 = masks(instruction, 0b1111, 13);
            
            if (sf && !S)
            {
                static const char *instructions[] = { "addg", "subg" };
                snprintf(context->decode_string, 512, "%s %s, %s, %s, %s", instructions[op], reg(rd, 1, sf, 0), reg(rn, 1, sf, 0), imm(uimm6 * 16, context, 0), imm(uimm4, context, 0));
            }

            break;
        }

        case 3:
        {
            uint8_t opc = masks(instruction, 0b11, 29);
            uint8_t N = masks(instruction, 0b1, 22);
            uint8_t immr = masks(instruction, 0b111111, 16);
            uint8_t imms = masks(instruction, 0b111111, 10);

            if (!sf && N)
                break;

            static const char *instructions[] = { "and", "orr", "eor", "ands" };

            uint64_t mask = decode_bit_masks(N, imms, immr, 32 << sf);

            if (opc == 1 && rn == 31 && move_wide_preferred(sf, N, imms, immr))
                snprintf(context->decode_string, 512, "mov %s, %s", reg(rd, 1, sf, 0), imm(mask, context, 1));
            else if (opc == 3 && rd == 31)
                snprintf(context->decode_string, 512, "tst %s, %s", reg(rn, 0, sf, 0), imm(mask, context, 1));
            else
                snprintf(context->decode_string, 512, "%s %s, %s, %s", instructions[opc], reg(rd, 1, sf, 0), reg(rn, 0, sf, 0), imm(mask, context, 0));

            break;
        }

        case 4:
        {
            uint8_t opc = masks(instruction, 0b11, 29);
            uint8_t hw = masks(instruction, 0b11, 21);
            uint16_t imm16 = masks(instruction, 0b1111111111111111, 5);
            
            if (opc == 1 || (!sf && (hw & 2)))
                break;

            static const char *instructions[] = { "movn", NULL, "movz", "movk" };

            if (opc == 0 && !(!imm16 && hw))
                snprintf(context->decode_string, 512, "mov %s, %s", reg(rd, 0, sf, 0), imm(imm16 << (hw * 16), context, 0));
            else if (opc == 2 && !(!imm16 && hw))
                snprintf(context->decode_string, 512, "mov %s, %s", reg(rd, 0, sf, 0), imm(imm16 << (hw * 16), context, 0));
            else
            {
                char add[12] = {0};
                if (hw)
                    snprintf(add, 12, ", %s", imm(hw * 16, context, 0));

                snprintf(context->decode_string, 512, "%s %s, %s%s", instructions[opc], reg(rd, 0, sf, 0), imm(imm16, context, 0), add);
            }

            break;
        }

        case 5:
        {
            int8_t opc = masks(instruction, 0b11, 29);
            bool N = masks(instruction, 0b1, 22);
            int8_t immr = masks(instruction, 0b111111, 16);
            int8_t imms = masks(instruction, 0b111111, 10);

            if (opc == 11 || (!sf && N))
                break;

            if (opc == 0)
            {
                // if (!sf && imms == 31)
                //     snprintf(context->decode_string, 512, "asr %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(immr, context, 0));
                // else if (!sf && imms == 63)
                //     snprintf(context->decode_string, 512, "asr %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(immr, context, 0));
                // else if ((uint8_t)imms < (uint8_t)immr)
                //     snprintf(context->decode_string, 512, "sbfiz %s, %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(imms & (sf ? 63 : 31), context, 0), imm(immr - 1, context, 0));
                // else if (bx_preferred(sf, opc >> 1, imms, immr))
                //     snprintf(context->decode_string, 512, "sbfx %s, %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(imms, context, 0), imm(imms + immr - 2, context, 0));
                // else if (!immr && imms == 0b111)
                //     snprintf(context->decode_string, 512, "sxtb %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0));
                // else if (!immr && imms == 0b1111)
                //     snprintf(context->decode_string, 512, "sxth %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0));
                // else if (!immr && imms == 0b11111)
                //     snprintf(context->decode_string, 512, "sxtw %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0));
                // else
                    snprintf(context->decode_string, 512, "sbfm %s, %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(immr, context, 0), imm(imms, context, 0));
            }
            else if (opc == 1)
            {
                // if (rn == 31 && (uint8_t)imms < (uint8_t)immr)
                //     snprintf(context->decode_string, 512, "bfc %s, %s, %s", reg(rd, 0, sf, 0), imm(imms & (sf ? 63 : 31), context, 0), imm(000000000000000000000000, context, 0));
                // else if (rn != 31 && (uint8_t)imms < (uint8_t)immr)
                //     snprintf(context->decode_string, 512, "bfi");
                // else if ((uint8_t)imms < (uint8_t)immr)
                //     snprintf(context->decode_string, 512, "bfxil");
                // else
                    snprintf(context->decode_string, 512, "bfm %s, %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(immr, context, 0), imm(imms, context, 0));
            }
            else
            {
                snprintf(context->decode_string, 512, "ubfm %s, %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(immr, context, 0), imm(imms, context, 0));
            }

            break;
        }

        case 6:
        {
            int8_t opc = masks(instruction, 0b11, 29);
            bool N = masks(instruction, 0b1, 22);
            bool o0 = masks(instruction, 0b1, 21);
            uint8_t rm = masks(instruction, 0b11111, 16);
            int8_t imms = masks(instruction, 0b111111, 10);

            if (opc || o0 || (!sf && imms & 0b100000))
                break;

            if (rn == rm)
                snprintf(context->decode_string, 512, "ror %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), imm(imms, context, 0));
            else
                snprintf(context->decode_string, 512, "extr %s, %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), reg(rm, 0, sf, 0), imm(imms, context, 0));

            break;
        }
    }
}

void disassemble_system(decode_context_t *context)
{
    uint32_t instruction = context->instruction;

    uint8_t op0 = masks(instruction, 0b111, 29);
    uint16_t op1 = masks(instruction, 0b11111111111111, 12);
    uint8_t op2 = mask(instruction, 0b11111);

    switch (op0)
    {
        case 0b010:
        {
            if ((~op1 & 0b11000000000000) && (~op2 & 0b10000))
            {
                int64_t imm19 = sign_extend(masks(instruction, 0b1111111111111111111, 5) * 4, 19);
                uint8_t cond = mask(instruction, 0b1111);

                snprintf(context->decode_string, 512, "b.%s %s", decode_condition(cond), symbol(context->pc + imm19, context));
            }

            break;
        }

        case 0b110:
        {
            if (!(op1 >> 12))
            {
                if (masks(instruction, 0b111, 2))
                    break;

                uint8_t op = (masks(instruction, 0b111, 21) << 2) | (mask(instruction, 0b11));
                uint16_t imm16 = masks(instruction, 0b1111111111111111, 5);

                switch (op)
                {
                    case 0b00001:
                    {
                        snprintf(context->decode_string, 512, "svc %s", imm(imm16, context, 0));
                        break;
                    }

                    case 0b00010:
                    {
                        snprintf(context->decode_string, 512, "hvc %s", imm(imm16, context, 0));
                        break;
                    }

                    case 0b00011:
                    {
                        snprintf(context->decode_string, 512, "smc %s", imm(imm16, context, 0));
                        break;
                    }

                    case 0b00100:
                    {
                        snprintf(context->decode_string, 512, "brk %s", imm(imm16, context, 0));
                        break;
                    }

                    case 0b01000:
                    {
                        snprintf(context->decode_string, 512, "hlt %s", imm(imm16, context, 0));
                        break;
                    }

                    case 0b10101:
                    {
                        snprintf(context->decode_string, 512, "dcps1 %s", imm(imm16, context, 0));
                        break;
                    }

                    case 0b10110:
                    {
                        snprintf(context->decode_string, 512, "dcps2 %s", imm(imm16, context, 0));
                        break;
                    }

                    case 0b10111:
                    {
                        snprintf(context->decode_string, 512, "dcps3 %s", imm(imm16, context, 0));
                        break;
                    }
                }
            
                break;
            }

            if (op1 >> 13)
            {
                uint8_t opc = masks(instruction, 0b1111, 21);
                uint8_t op2 = masks(instruction, 0b11111, 16);
                uint8_t op3 = masks(instruction, 0b111111, 10);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t op4 = mask(instruction, 0b11111);

                if (op2 != 0b11111)
                    break;

                switch (opc)
                {
                    case 0b0000:
                    {
                        if (!op3 && !op4)
                        {
                            snprintf(context->decode_string, 512, "br %s", reg(rn, 0, 1, 0));
                            break;
                        }
                        else if (op4 == 0b11111)
                        {
                            // armv8.3

                            if (op3 == 0b000010)
                                snprintf(context->decode_string, 512, "braaz %s", reg(rn, 0, 1, 0));
                            else if (op3 == 0b000011)
                                snprintf(context->decode_string, 512, "brabz %s", reg(rn, 0, 1, 0));
                        }

                        break;
                    }

                    case 0b0001:
                    {
                        if (!op3 && !op4)
                        {
                            snprintf(context->decode_string, 512, "blr %s", reg(rn, 0, 1, 0));
                            break;
                        }
                        else if (op4 == 0b11111)
                        {
                            // armv8.3

                            if (op3 == 0b000010)
                                snprintf(context->decode_string, 512, "blraaz %s", reg(rn, 0, 1, 0));
                            else if (op3 == 0b000011)
                                snprintf(context->decode_string, 512, "blrabz %s", reg(rn, 0, 1, 0));
                        }

                        break;
                    }

                    case 0b0010:
                    {
                        if (!op3 && !op4)
                        {
                            char add[5] = {0};
                            if (rn != 30)
                                snprintf(add, 5, " %s", reg(rn, 0, 1, 0));

                            snprintf(context->decode_string, 512, "ret%s", add);
                            break;
                        }
                        else if (op4 == 0b11111 && rn == 0b11111)
                        {
                            // armv8.3

                            if (op3 == 0b000010)
                                snprintf(context->decode_string, 512, "retaa");
                            else if (op3 == 0b000011)
                                snprintf(context->decode_string, 512, "retab");
                        }

                        break;
                    }

                    case 0b0100:
                    {
                        if (rn != 0b11111)
                            break;

                        if (!op3 && !op4)
                        {
                            snprintf(context->decode_string, 512, "eret");
                            break;
                        }
                        else if (op4 == 0b11111)
                        {
                            // armv8.3

                            if (op3 == 0b000010)
                                snprintf(context->decode_string, 512, "eretaa");
                            else if (op3 == 0b000011)
                                snprintf(context->decode_string, 512, "eretab");
                        }

                        break;
                    }

                    case 0b0101:
                    {
                        if (!op3 && !op4 && rn == 0b11111)
                            snprintf(context->decode_string, 512, "drps");

                        break;
                    }

                    case 0b1000:
                    {
                        if (op3 == 0b000010)
                            snprintf(context->decode_string, 512, "braa %s, %s", reg(rn, 0, 1, 0), reg(op4, 1, 1, 0));
                        else if (op3 == 0b000011)
                            snprintf(context->decode_string, 512, "brab %s, %s", reg(rn, 0, 1, 0), reg(op4, 1, 1, 0));

                        break;
                    }

                    case 0b1001:
                    {
                        if (op3 == 0b000010)
                            snprintf(context->decode_string, 512, "blraa %s, %s", reg(rn, 0, 1, 0), reg(op4, 1, 1, 0));
                        else if (op3 == 0b000011)
                            snprintf(context->decode_string, 512, "blrab %s, %s", reg(rn, 0, 1, 0), reg(op4, 1, 1, 0));

                        break;
                    }
                }

                break;
            }

            if (op1 == 0b01000000110010 && op2 == 0b11111)
            {
                uint8_t op = (masks(instruction, 0b1111, 8) << 3) | (masks(instruction, 0b111, 5));

                switch (op)
                {
                    case 0b0000000:
                    {
                        snprintf(context->decode_string, 512, "nop");
                        break;
                    }

                    case 0b0000001:
                    {
                        snprintf(context->decode_string, 512, "yield");
                        break;
                    }

                    case 0b0000010:
                    {
                        snprintf(context->decode_string, 512, "wfe");
                        break;
                    }

                    case 0b0000011:
                    {
                        snprintf(context->decode_string, 512, "wfi");
                        break;
                    }

                    case 0b0000100:
                    {
                        snprintf(context->decode_string, 512, "sev");
                        break;
                    }

                    case 0b0000101:
                    {
                        snprintf(context->decode_string, 512, "sevl");
                        break;
                    }

                    case 0b0000111:
                    {
                        // armv8.3

                        snprintf(context->decode_string, 512, "xpaclri");
                        break;
                    }

                    case 0b0001000:
                    {
                        // armv8.3

                        snprintf(context->decode_string, 512, "pacia1716");
                        break;
                    }

                    case 0b0001010:
                    {
                        // armv8.3
                        
                        snprintf(context->decode_string, 512, "pacib1716");
                        break;
                    }

                    case 0b0001100:
                    {
                        // armv8.3
                        
                        snprintf(context->decode_string, 512, "autia1716");
                        break;
                    }

                    case 0b0001110:
                    {
                        // armv8.3
                        
                        snprintf(context->decode_string, 512, "autib1716");
                        break;
                    }

                    case 0b0010000:
                    {
                        snprintf(context->decode_string, 512, "esb");
                        break;
                    }

                    case 0b0010001:
                    {
                        snprintf(context->decode_string, 512, "psb csync");
                        break;
                    }

                    case 0b0010010:
                    {
                        // armv8.4

                        snprintf(context->decode_string, 512, "tsb csync");
                        break;
                    }

                    case 0b0010100:
                    {
                        snprintf(context->decode_string, 512, "csdb");
                        break;
                    }
                }
            
                uint8_t crm = masks(instruction, 0b1111, 8);
                uint8_t op2 = masks(instruction, 0b111, 5);

                if (crm == 0b11)
                {
                    // armv8.3
                        
                    static const char *instructions[] = {"paciaz", "paciasp", "pacibz", "pacibsp", "autiza", "autiasp", "autizb", "autibsp"};
                    strncpy(context->decode_string, instructions[op2], 511);
                    break;
                }

                if (crm == 0b100 && !(op2 & 1))
                {
                    // armv8.5
                    
                    uint8_t targets = masks(instruction, 0b11, 6);

                    const char *add = {0};

                    switch (targets)
                    {
                        case 0b01: add = " c"; break;
                        case 0b10: add = " j"; break;
                        case 0b11: add = " jc"; break;
                    }

                    snprintf(context->decode_string, 512, "bti%s", add);
                    break;
                }
            }
            else if (op1 == 0b01000000110011)
            {
                uint8_t crm = masks(instruction, 0b1111, 8);
                uint8_t op2 = masks(instruction, 0b111, 5);
                uint8_t rt = mask(instruction, 0b11111);

                if (rt == 0b11111)
                {
                    switch (op2)
                    {
                        case 0b010:
                        {
                            snprintf(context->decode_string, 512, "clrex %s", imm(crm, context, 0));
                            break;
                        }

                        case 0b100:
                        {
                            if (crm == 0b100)
                                snprintf(context->decode_string, 512, "pssbb");

                            break;
                        }

                        case 0b101:
                        {
                            snprintf(context->decode_string, 512, "dmb %s", decode_barrier(crm));
                            break;
                        }

                        case 0b110:
                        {
                            snprintf(context->decode_string, 512, "isb %s", imm(crm, context, 0));
                            break;
                        }

                        case 0b111:
                        {
                            snprintf(context->decode_string, 512, "sb");
                            break;
                        }
                    }
                }
            }
            else if ((op1 & 0b11111110001111) == 0b01000000000100)
            {
                uint8_t rt = mask(instruction, 0b11111);

                if (rt == 0b11111)
                {
                    uint8_t crm = masks(instruction, 0b1111, 8);
                    uint8_t op1 = masks(instruction, 0b111, 16);
                    uint8_t op2 = masks(instruction, 0b111, 5);

                    if (!op1)
                    {
                        switch (op2)
                        {
                            case 0b000:
                            {
                                // armv8.4

                                strcpy(context->decode_string, "cfinv");
                                break;
                            }

                            case 0b001:
                            {
                                // armv8.5

                                strcpy(context->decode_string, "xaflag");
                                break;
                            }

                            case 0b010:
                            {
                                // armv8.5

                                strcpy(context->decode_string, "axflag");
                                break;
                            }
                        }
                    }

                    snprintf(context->decode_string, 512, "msr %s, %s", decode_pstate((op1 << 3) | op2), imm(crm, context, 0));
                    break;
                }

                break;
            }
            else if ((op1 & 0b11110110000000) == 0b01000010000000)
            {
                uint8_t op1 = masks(instruction, 0b111, 16);
                uint8_t crn = masks(instruction, 0b1111, 12);
                uint8_t crm = masks(instruction, 0b1111, 8);
                uint8_t op2 = masks(instruction, 0b111, 5);
                uint8_t rt = mask(instruction, 0b11111);

                if (masks(instruction, 0b1, 21))
                    snprintf(context->decode_string, 512, "sysl %s, %s, %d, %d, %s", reg(rt, 0, 1, 0), imm(op1, context, 0), crn, crm, imm(op2, context, 0));
                else
                    snprintf(context->decode_string, 512, "sys %s, %d, %d, %s, %s", imm(op1, context, 0), crn, crm, imm(op2, context, 0), reg(rt, 0, 1, 0));
            }
            else if ((op1 & 0b11110100000000) == 0b01000100000000)
            {
                uint8_t op0 = masks(instruction, 0b1, 19) ? 3 : 2;
                uint8_t op1 = masks(instruction, 0b111, 16);
                uint8_t crn = masks(instruction, 0b1111, 12);
                uint8_t crm = masks(instruction, 0b1111, 8);
                uint8_t op2 = masks(instruction, 0b111, 5);
                uint8_t rt = mask(instruction, 0b11111);

                if (masks(instruction, 0b1, 21))
                    snprintf(context->decode_string, 512, "mrs %s, s%d_%d_%d_%d_%d", reg(rt, 0, 1, 0), op0, op1, crn, crm, op2);
                else
                    snprintf(context->decode_string, 512, "msr s%d_%d_%d_%d_%d, %s", op0, op1, crn, crm, op2, reg(rt, 0, 1, 0));
            }

            break;
        }
    
        case 0b100:
        case 0b000:
        {
            int32_t imm26 = sign_extend(mask(instruction, 0b11111111111111111111111111), 26);
            snprintf(context->decode_string, 512, "%s %s", masks(instruction, 0b1, 31) ? "bl" : "b", symbol(context->pc + (imm26 * 4), context));
            break;
        }

        case 0b101:
        case 0b001:
        {
            if (op1 >> 13)
            {
                bool sf = masks(instruction, 0b1, 31);
                bool op = masks(instruction, 0b1, 24);
                uint8_t b40 = masks(instruction, 0b11111, 19);
                int16_t imm14 = sign_extend(masks(instruction, 0b11111111111111, 5), 14);
                uint8_t rt = mask(instruction, 0b11111);

                const char *instruction = op ? "tbnz" : "tbz";
                snprintf(context->decode_string, 512, "%s %s, %s, %s", instruction, reg(rt, 0, sf, 0), imm((sf << 5) | b40, context, 0), symbol(context->pc + (imm14 * 4), context));
            }
            else
            {
                bool sf = masks(instruction, 0b1, 31);
                bool op = masks(instruction, 0b1, 24);
                int32_t imm19 = sign_extend(masks(instruction, 0b1111111111111111111, 5), 19);
                uint8_t rt = mask(instruction, 0b11111);

                const char *instruction = op ? "cbnz" : "cbz";
                snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rt, 0, sf, 0), symbol(context->pc + (imm19 * 4), context));
            }

            break;
        }
    }
}

void disassemble_loads_stores(decode_context_t *context)
{
    uint32_t instruction = context->instruction;

    uint8_t op0 = masks(instruction, 0b1111, 28);
    bool op1 = masks(instruction, 0b1, 26);
    uint8_t op2 = masks(instruction, 0b11, 23);
    uint8_t op3 = masks(instruction, 0b111111, 16);
    uint8_t op4 = masks(instruction, 0b11, 10);

    if (op1 && !(op0 & 0b11))
    {
        if (op0 >> 3)
            return;

        if (op2 & 0b10)
        {
            // advanced SIMD load/store single structure
            // advanced SIMD load/store single structure (post-indexed)
            // from what i can tell this is almost never used so i'll do it later.
        }
        else
        {
            bool post_index = op2 & 1;
            if ((!post_index && op3) || (post_index && (op3 >> 5)))
                return;

            bool Q = masks(instruction, 0b1, 30);
            bool L = masks(instruction, 0b1, 22);
            uint8_t opcode = masks(instruction, 0b1111, 12);
            uint8_t rn = masks(instruction, 0b11111, 5);
            uint8_t rt = mask(instruction, 0b11111);

            const char *instruction;
            uint8_t rc;

            switch (opcode)
            {
                case 0b0000:
                {
                    instruction = L ? "ld4" : "st4";
                    rc = 4;
                    break;
                }

                case 0b0010:
                {
                    instruction = L ? "ld1" : "st1";
                    rc = 4;
                    break;
                }

                case 0b0100:
                {
                    instruction = L ? "ld3" : "st3";
                    rc = 3;
                    break;
                }

                case 0b0110:
                {
                    instruction = L ? "ld1" : "st1";
                    rc = 3;
                    break;
                }

                case 0b0111:
                {
                    instruction = L ? "ld1" : "st1";
                    rc = 1;
                    break;
                }

                case 0b1000:
                {
                    instruction = L ? "ld2" : "st2";
                    rc = 2;
                    break;
                }

                case 0b1010:
                {
                    instruction = L ? "ld1" : "st1";
                    rc = 2;
                    break;
                }

                default: return;
            }

            const char *specifier = decode_specifier((op4 << 1) | Q);

            char sregs[64] = {0};
            int loc = 0;

            for (int i = 0; i < rc; i++)
                loc += sprintf(sregs + loc, "v%d.%s%s", (rt + i) & 0x1f, specifier, (i == rc - 1) ? "" : ", ");

            char add[12] = {0};
            if (post_index)
            {
                uint8_t rm = op3 & 0b11111;

                if (rm == 0b11111)
                    snprintf(add, 12, ", %s", imm(32 << Q, context, 0));
                else
                    snprintf(add, 12, ", %s", reg(rm, 0, 1, 0));
            }

            snprintf(context->decode_string, 512, "%s {%s}, [%s]%s", instruction, sregs, reg(rn, 1, 1, 0), add);
        }
    }
    else if (!op1)
    {
        if (op0 == 0b1101 && (op2 & 0b10) && (op3 & 0b100000))
        {
            // armv8.5

            uint8_t opc = masks(instruction, 0b11, 22);
            int16_t imm9 = sign_extend(masks(instruction, 0b111111111, 12), 9);
            uint8_t op2 = masks(instruction, 0b11, 10);
            uint8_t rn = masks(instruction, 0b11111, 5);
            uint8_t rt = mask(instruction, 0b11111);

            switch ((opc << 2) | op2)
            {
                case 0b0000:
                {
                    if (imm9)
                        break;

                    snprintf(context->decode_string, 512, "stzgm %s, [%s]", reg(rt, 0, 1, 0), reg(rn, 1, 1, 0));
                    break;
                }

                case 0b0001:
                {
                    snprintf(context->decode_string, 512, "stg %s, [%s], %s", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 1));
                    break;
                }

                case 0b0010:
                {
                    char add[24] = {0};
                    if (imm9)
                        snprintf(add, 24, ", %s", imm(imm9, context, 1));

                    snprintf(context->decode_string, 512, "stg %s, [%s%s]", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), add);
                    break;
                }

                case 0b0011:
                {
                    snprintf(context->decode_string, 512, "stg %s, [%s, %s]!", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 1));
                    break;
                }

                case 0b0100:
                {
                    char add[24] = {0};
                    if (imm9)
                        snprintf(add, 24, ", %s", imm(imm9, context, 1));

                    snprintf(context->decode_string, 512, "ldg %s, [%s%s]", reg(rt, 0, 1, 0), reg(rn, 1, 1, 0), add);
                    break;
                }

                case 0b0101:
                {
                    snprintf(context->decode_string, 512, "stzg %s, [%s], %s", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 0));
                    break;
                }

                case 0b0110:
                {
                    char add[24] = {0};
                    if (imm9)
                        snprintf(add, 24, ", %s", imm(imm9, context, 1));

                    snprintf(context->decode_string, 512, "stzg %s, [%s%s]", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), add);
                    break;
                }

                case 0b0111:
                {
                    snprintf(context->decode_string, 512, "stzg %s, [%s, %s]!", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 0));
                    break;
                }

                case 0b1001:
                {
                    snprintf(context->decode_string, 512, "st2g %s, [%s], %s", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 0));
                    break;
                }

                case 0b1010:
                {
                    char add[24] = {0};
                    if (imm9)
                        snprintf(add, 24, ", %s", imm(imm9, context, 1));

                    snprintf(context->decode_string, 512, "st2g %s, [%s%s]", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), add);
                    break;
                }

                case 0b1011:
                {
                    snprintf(context->decode_string, 512, "st2g %s, [%s, %s]!", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 0));
                    break;
                }

                case 0b1000:
                {
                    if (!imm9)
                        snprintf(context->decode_string, 512, "stgm %s, [%s]", reg(rt, 0, 1, 0), reg(rn, 1, 1, 0));

                    break;
                }

                case 0b1101:
                {
                    snprintf(context->decode_string, 512, "stz2g %s, [%s], %s", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 0));
                    break;
                }

                case 0b1110:
                {
                    char add[24] = {0};
                    if (imm9)
                        snprintf(add, 24, ", %s", imm(imm9, context, 1));

                    snprintf(context->decode_string, 512, "stz2g %s, [%s%s]", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), add);
                    break;
                }

                case 0b1111:
                {
                    snprintf(context->decode_string, 512, "stz2g %s, [%s, %s]!", reg(rt, 1, 1, 0), reg(rn, 1, 1, 0), imm(imm9, context, 0));
                    break;
                }

                case 0b1100:
                {
                    if (!imm9)
                        snprintf(context->decode_string, 512, "ldgm %s, [%s]", reg(rt, 0, 1, 0), reg(rn, 1, 1, 0));

                    break;
                }
            }
            
            return;
        }
        else if (!(op0 & 0b0011) && !(op2 & 0b10))
        {
            uint8_t size = masks(instruction, 0b11, 30);
            bool o2 = masks(instruction, 0b1, 23);
            bool L = masks(instruction, 0b1, 22);
            bool o1 = masks(instruction, 0b1, 21);
            uint8_t rs = masks(instruction, 0b11111, 16);
            bool o0 = masks(instruction, 0b1, 15);
            uint8_t rt2 = masks(instruction, 0b11111, 10);
            uint8_t rn = masks(instruction, 0b11111, 5);
            uint8_t rt = mask(instruction, 0b11111);

            if (size & 0b10)
            {
                bool sf = size & 1;

                if (o2)
                {
                    uint8_t opc = (L << 1) | o0;

                    if (o1)
                    {
                        static const char *instructions[] = {"cas", "casl", "casa", "casal"};
                        snprintf(context->decode_string, 512, "%s %s, %s, [%s]", instructions[opc], reg(rs, 0, sf, 0), reg(rt, 0, sf, 0), reg(rn, 1, 1, 0));
                    }
                    else if (rs == 0b11111 && rt2 == 0b11111)
                    {
                        if (opc == 0 || opc == 2)
                        {
                            // armv8.1
                        }

                        static const char *instructions[] = {"stllr", "stlr", "ldlar", "ldar"};
                        snprintf(context->decode_string, 512, "%s %s, [%s]", instructions[opc], reg(rt, 0, sf, 0), reg(rn, 1, 1, 0));
                    }
                }
                else
                {
                    if (L)
                    {
                        if (rs != 0b11111)
                            return;

                        if (o1)
                            snprintf(context->decode_string, 512, "%s %s, %s, [%s]", o0 ? "ldaxp" : "ldxp", reg(rt, 0, sf, 0), reg(rt2, 0, sf, 0), reg(rn, 0, 1, 0));
                        else if (rt2 == 0b11111)
                            snprintf(context->decode_string, 512, "%s %s, [%s]", o0 ? "ldaxr" : "ldxr", reg(rt, 0, sf, 0), reg(rn, 0, 1, 0));
                    }
                    else
                    {
                        if (o1)
                            snprintf(context->decode_string, 512, "%s %s, %s, %s, [%s]", o0 ? "stlxp" : "stxp", reg(rs, 0, sf, 0), reg(rt, 0, sf, 0), reg(rt2, 0, sf, 0), reg(rn, 1, 1, 0));
                        else if (rt2 == 0b11111)
                            snprintf(context->decode_string, 512, "%s %s, %s, [%s]", o0 ? "stlxr" : "stxr", reg(rs, 0, sf, 0), reg(rt, 0, sf, 0), reg(rn, 1, 1, 0));
                    }
                }

                return;
            }

            if (rt2 != 0b11111)
                return;

            if (o1)
            {
                if (o2)
                {
                    // armv8.1
                    uint8_t opc = (size << 2) | (L << 1) | o0;
                    static const char *instructions[] = {"casb", "caslb", "casab", "casalb", "cash", "caslh", "casah", "casalh"};
                    snprintf(context->decode_string, 512, "%s %s, %s, [%s]", instructions[opc], reg(rs, 0, 0, 0), reg(rt, 0, 0, 0), reg(rn, 1, 1, 0));
                }
                else
                {
                    // armv8.1
                    uint8_t opc = (L << 1) | o0;
                    static const char *instructions[] = {"casp", "caspl", "caspa", "caspal"};
                    snprintf(context->decode_string, 512, "%s %s, %s, %s, %s, [%s]", instructions[opc], reg(rs, 0, size, 0), reg(rs + 1, 0, size, 0), reg(rt, 0, size, 0), reg(rt + 1, 0, size, 0), reg(rn, 1, 1, 0));
                }
            }
            else
            {
                if (L)
                {
                    if (rs != 0b11111)
                        return;

                    uint8_t opc = (size << 2) | (o2 << 1) | o0;

                    if (opc == 2 || opc == 6)
                    {
                        // armv8.1
                    }

                    static const char *instructions[] = {"ldxrb", "ldaxrb", "ldlarb", "ldarb", "ldxrh", "ldaxhr", "ldlarh", "ldarh"};
                    snprintf(context->decode_string, 512, "%s %s, [%s]", instructions[opc], reg(rt, 0, 0, 0), reg(rn, 1, 1, 0));
                }
                else
                {
                    uint8_t opc = (size << 2) | (o2 << 1) | o0;

                    if (opc == 2 || opc == 6)
                    {
                        // armv8.1
                    }

                    static const char *instructions[] = {"stxrb", "stlxrb", "stllrb", "stlrb", "stxrh", "stlxrh", "stllrh", "stlrh"};
                    snprintf(context->decode_string, 512, "%s %s, %s, [%s]", instructions[opc], reg(rs, 0, 0, 0), reg(rt, 0, 0, 0), reg(rn, 1, 1, 0));
                }
            }

            return;
        }
    }

    switch (op0 & 0b11)
    {
        case 0b01:
        {
            if (!(op2 & 0b10))
            {
                uint8_t opc = masks(instruction, 0b11, 30);
                bool V = masks(instruction, 0b1, 26);
                int32_t imm19 = sign_extend(masks(instruction, 0b1111111111111111111, 5), 19);
                uint8_t rt = mask(instruction, 0b11111);

                if (V)
                {
                    if (opc == 0b11)
                        return;

                    uint8_t bits = 32 * (1 << opc);
                    snprintf(context->decode_string, 512, "ldr %s, %s", reg(rt, 0, bits, 1), symbol(context->pc + (imm19 * 4), context));
                }
                else
                {
                    if (opc & 0b10)
                    {
                        if (opc & 1)
                        {
                            char prefetch[24] = {0};
                            decode_prefetch(rt, prefetch);
                            snprintf(context->decode_string, 512, "prfm %s, %s", prefetch, symbol(context->pc + (imm19 * 4), context));
                        }
                        else
                        {
                            snprintf(context->decode_string, 512, "ldrsw %s, %s", reg(rt, 0, 1, 0), symbol(context->pc + (imm19 * 4), context));
                        }
                    }
                    else
                    {
                        snprintf(context->decode_string, 512, "ldr %s, %s", reg(rt, 0, opc, 0), symbol(context->pc + (imm19 * 4), context));
                    }
                }
            }
            else if (!op1 && (op2 & 0b10) && !(op3 & 0b100000) && !op4)
            {
                // armv8.4

                uint8_t size = masks(instruction, 0b11, 30);
                uint8_t opc = masks(instruction, 0b11, 22);
                uint16_t imm9 = masks(instruction, 0b111111111, 12);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t rt = mask(instruction, 0b11111);

                if (opc & 0b10)
                {
                    if (size == 0b11 || (size == 10 && opc == 11))
                        return;

                    bool sf = !(opc & 1);

                    char add[24] = {0};
                    if (imm9)
                        snprintf(add, 24, ", %s", imm(imm9, context, 0));

                    const char *instructions[] = {"ldapursb", "ldapursh", "ldapursw"};
                    snprintf(context->decode_string, 512, "%s %s, [%s%s]", instructions[size], reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), add);
                }
                else
                {
                    bool sf = (size == 0b11) ? 1 : 0;
                    uint8_t op = (size << 2) | opc;

                    char add[24] = {0};
                    if (imm9)
                        snprintf(add, 24, ", %s", imm(imm9, context, 0));

                    const char *instructions[] = {"stlurb", "ldapurb", "stlurh", "ldapurh", "stlur", "ldapur", "stlur", "ldapur"};
                    snprintf(context->decode_string, 512, "%s %s, [%s%s]", instructions[op], reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), add);
                }
            }

            break;
        }

        case 0b10:
        {
            uint8_t opc = masks(instruction, 0b11, 30);
            bool V = masks(instruction, 0b1, 26);
            bool L = masks(instruction, 0b1, 22);
            int8_t imm7 = sign_extend(masks(instruction, 0b1111111, 15), 7);
            uint8_t rt2 = masks(instruction, 0b11111, 10);
            uint8_t rn = masks(instruction, 0b11111, 5);
            uint8_t rt = mask(instruction, 0b11111);

            switch (op2)
            {
                case 0b00:
                {
                    if (opc == 0b11)
                        return;

                    const char *instruction = L ? "ldnp" : "stnp";

                    char add[24] = {0};
                    if (imm7)
                        snprintf(add, 24, ", %s", imm(imm7 * (4 * (1 << opc)), context, 1));

                    if (V)
                    {
                        uint8_t bits = 32 * (1 << opc);
                        snprintf(context->decode_string, 512, "%s %s, %s, [%s%s]", instruction, reg(rt, 0, bits, 1), reg(rt2, 0, bits, 1), reg(rn, 1, 1, 0), add);
                    }
                    else
                    {
                        if (opc == 0b01)
                            return;

                        snprintf(context->decode_string, 512, "%s %s, %s, [%s%s]", instruction, reg(rt, 0, opc >> 1, 0), reg(rt2, 0, opc >> 1, 0), reg(rn, 1, 1, 0), add);
                    }

                    break;
                }
            
                case 0b01:
                case 0b10:
                case 0b11:
                {
                    if (opc == 0b11)
                        return;

                    const char *instruction = L ? "ldp" : "stp";
                    
                    if (V)
                    {
                        char add[24] = {0};
                        if (imm7)
                            snprintf(add, 24, ", %s", imm(imm7 * (4 * (1 << opc)), context, 1));

                        uint8_t bits = 32 * (1 << opc);

                        static const char *formats[] = {"%s %s, %s, [%s]%s", "%s %s, %s, [%s%s]", "%s %s, %s, [%s%s]!"};
                        snprintf(context->decode_string, 512, formats[op2 - 1], instruction, reg(rt, 0, bits, 1), reg(rt2, 0, bits, 1), reg(rn, 1, 1, 0), add);
                    }
                    else
                    {
                        if (!L)
                        {
                            // armv8.5
                        }

                        if (opc == 0b01)
                            instruction = L ? "ldpsw" : "stgp";

                        char add[24] = {0};
                        if (imm7)
                            snprintf(add, 24, ", %s", imm(imm7 * (4 * (1 << (opc >> 1))), context, 1));

                        bool sf = (opc == 0) ? 0 : 1;

                        static const char *formats[] = {"%s %s, %s, [%s]%s", "%s %s, %s, [%s%s]", "%s %s, %s, [%s%s]!"};
                        snprintf(context->decode_string, 512, formats[op2 - 1], instruction, reg(rt, 0, sf, 0), reg(rt2, 0, sf, 0), reg(rn, 1, 1, 0), add);
                    }

                    break;
                }
            }

            break;
        }

        case 0b11:
        {
            if (op2 & 0b10)
            {
                uint8_t size = masks(instruction, 0b11, 30);
                bool V = masks(instruction, 0b1, 26);
                uint8_t opc = masks(instruction, 0b11, 22);
                uint16_t imm12 = masks(instruction, 0b111111111111, 10);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t rt = mask(instruction, 0b11111);

                char add[24] = {0};

                if (V)
                {
                    uint8_t bits = 8 * (1 << size);

                    if (opc & 0b10)
                    {
                        if (!size)
                            bits = 128;
                        else
                            return;
                    }

                    char add[24] = {0};
                    if (imm12)
                        snprintf(add, 24, ", %s", imm(imm12 * (bits / 8), context, 0));

                    snprintf(context->decode_string, 512, "%s %s, [%s%s]", (opc & 1) ? "ldr" : "str", reg(rt, 0, bits, 1), reg(rn, 1, 1, 0), add);
                }
                else
                {
                    if (opc & 0b10)
                    {
                        if (size == 0b11)
                        {
                            if (opc & 0b1)
                                return;

                            char prefetch[24] = {0};
                            decode_prefetch(rt, prefetch);

                            snprintf(add, 24, ", %s", imm(imm12 * 8, context, 0));
                            snprintf(context->decode_string, 512, "prfm %s, [%s%s]", prefetch, reg(rn, 1, 1, 0), add);

                            break;
                        }

                        if (size == 0b10 && opc == 0b11)
                            return;

                        static const char *instructions[] = {"ldrsb", "ldrsh", "ldrsw"};

                        if (imm12)
                            snprintf(add, 24, ", %s", imm(imm12 * (1 << size), context, 0));

                        snprintf(context->decode_string, 512, "%s %s, [%s%s]", instructions[size], reg(rt, 0, (opc == 0b10) ? 64 : 32, 0), reg(rn, 1, 1, 0), add);
                        break;
                    }
                    else
                    {
                        bool sf = (size == 0b11);

                        static const char *instructions[] = {"strb", "strh", "str", "ldrb", "ldrh", "ldr"};
                        const char *instruction = instructions[size + ((opc & 1) ? 3 : 0) - sf];

                        if (imm12)
                            snprintf(add, 24, ", %s", imm(imm12 * (1 << size), context, 0));

                        snprintf(context->decode_string, 512, "%s %s, [%s%s]", instruction, reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), add);
                        break;
                    }
                }
            }
            else
            {
                if (op2 & 0b10)
                    return;

                if (op3 >> 5)
                {
                    switch (op4)
                    {
                        case 0b00:
                        {
                            // atomic memory operations
                            // fuck this group
                            break;
                        }

                        case 0b10:
                        {
                            uint8_t size = masks(instruction, 0b11, 30);
                            bool V = masks(instruction, 0b1, 26);
                            uint8_t opc = masks(instruction, 0b11, 22);
                            uint8_t rm = masks(instruction, 0b11111, 16);
                            uint8_t option = masks(instruction, 0b111, 13);
                            bool S = masks(instruction, 0b1, 12);
                            uint8_t rn = masks(instruction, 0b11111, 5);
                            uint8_t rt = mask(instruction, 0b11111);

                            if (V)
                            {
                                const char *instruction = (opc & 1) ? "ldr" : "str";
                                uint8_t amount = 0;
                                bool extend = 1;
                                bool sf = 0;

                                switch (size)
                                {
                                    case 0b00:
                                    {
                                        if (opc & 0b10)
                                            amount = 4;
                                        else
                                            amount = 0;

                                        break;
                                    }

                                    case 0b01: amount = 1; break;
                                    case 0b10: amount = 2; break;
                                    case 0b11: amount = 3; break;
                                }

                                char add[32] = {0};

                                if (extend)
                                {
                                    if (option != 0b011 || S)
                                        snprintf(add, 32, ", %s %s", decode_reg_extend(option), imm(amount, context, 0));
                                }
                                else
                                {
                                    if (S)
                                        snprintf(add, 32, ", lsl %s", imm(0, context, 0));
                                }
                                
                                snprintf(context->decode_string, 512, "%s %s, [%s, %s%s]", instruction, reg(rt, 0, 8 << amount, 1), reg(rn, 1, 1, 0), reg(rm, 0, option & 1, 0), add);
                            }
                            else
                            {
                                const char *instruction;
                                uint8_t amount = 0;
                                bool extend = 1;
                                bool sf = 0;

                                switch (size)
                                {
                                    case 0b00:
                                    {
                                        if (option == 0b011)
                                            extend = 0;
                                        
                                        switch (opc)
                                        {
                                            case 0b00:
                                            {
                                                instruction = "strb";
                                                break;
                                            }

                                            case 0b01:
                                            {
                                                instruction = "ldrb";
                                                break;
                                            }

                                            case 0b10:
                                            {
                                                instruction = "ldrsb";
                                                sf = 1;
                                                break;
                                            }

                                            case 0b11:
                                            {
                                                instruction = "ldrsb";
                                                break;
                                            }
                                        }

                                        break;
                                    }

                                    case 0b01:
                                    {
                                        amount = 1;

                                        switch (opc)
                                        {
                                            case 0b00:
                                            {
                                                instruction = "strh";
                                                break;
                                            }

                                            case 0b01:
                                            {
                                                instruction = "ldrh";
                                                break;
                                            }

                                            case 0b10:
                                            {
                                                instruction = "ldrsh";
                                                sf = 1;
                                                break;
                                            }

                                            case 0b11:
                                            {
                                                instruction = "ldrsh";
                                                break;
                                            }
                                        }

                                        break;
                                    }

                                    case 0b10:
                                    {
                                        amount = 2;

                                        switch (opc)
                                        {
                                            case 0b00:
                                            {
                                                instruction = "str";
                                                break;
                                            }

                                            case 0b01:
                                            {
                                                instruction = "ldr";
                                                break;
                                            }

                                            case 0b10:
                                            {
                                                instruction = "ldrsw";
                                                sf = 1;
                                                break;
                                            }

                                            case 0b11: return;
                                        }

                                        break;
                                    }

                                    case 0b11:
                                    {
                                        amount = 3;
                                        sf = 1;

                                        switch (opc)
                                        {
                                            case 0b00:
                                            {
                                                instruction = "str";
                                                break;
                                            }

                                            case 0b01:
                                            {
                                                instruction = "ldr";
                                                break;
                                            }

                                            case 0b10:
                                            {
                                                // prfm
                                                return;
                                            }

                                            case 0b11: return;
                                        }

                                        break;
                                    }
                                }
                            
                                char add[32] = {0};

                                if (extend)
                                {
                                    if (option != 0b011 || S)
                                        snprintf(add, 32, ", %s %s", decode_reg_extend(option), imm(amount, context, 0));
                                }
                                else
                                {
                                    if (S)
                                        snprintf(add, 32, ", lsl %s", imm(0, context, 0));
                                }

                                snprintf(context->decode_string, 512, "%s %s, [%s, %s%s]", instruction, reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), reg(rm, 0, option & 1, 0), add);
                            }

                            break;
                        }

                        case 0b01:
                        case 0b11:
                        {
                            // armv8.3

                            uint8_t size = masks(instruction, 0b11, 30);
                            bool V = masks(instruction, 0b1, 26);
                            bool M = masks(instruction, 0b1, 23);
                            bool S = masks(instruction, 0b1, 22);
                            int16_t imm9 = sign_extend(masks(instruction, 0b111111111, 12), 9);
                            bool W = masks(instruction, 0b1, 11);
                            uint8_t rn = masks(instruction, 0b11111, 5);
                            uint8_t rt = mask(instruction, 0b11111);

                            if (V || size != 0b11)
                                return;

                            const char *instruction = M ? "ldrab" : "ldraa";

                            char add[16] = {0};
                            if (imm9)
                                snprintf(add, 16, ", %s", imm(imm9, context, 1));

                            snprintf(context->decode_string, 512, "%s %s, [%s%s]%c", instruction, reg(rt, 0, 1, 0), reg(rn, 1, 1, 0), add, W ? '!' : '\0');
                            break;
                        }
                    }
                }
                else
                {
                    switch (op4)
                    {
                        case 0b00:
                        {
                            uint8_t size = masks(instruction, 0b11, 30);
                            bool V = masks(instruction, 0b1, 26);
                            uint8_t opc = masks(instruction, 0b11, 22);
                            int16_t imm9 = sign_extend(masks(instruction, 0b111111111, 12), 9);
                            uint8_t rn = masks(instruction, 0b11111, 5);
                            uint8_t rt = mask(instruction, 0b11111);

                            bool unscaled = opc >> 1;
                            bool variant = opc & 1;

                            if (V)
                            {
                                uint8_t bits;

                                if (unscaled)
                                {
                                    if (size == 0b00)
                                        bits = 128;
                                    else
                                        return;
                                }
                                else
                                {
                                    bits = 8 << size;
                                }

                                char add[12] = {0};
                                if (imm9)
                                    snprintf(add, 12, ", %s", imm(imm9, context, 1));

                                snprintf(context->decode_string, 512, "%s %s, [%s%s]", variant ? "ldur" : "stur", reg(rt, 0, bits, 1), reg(rn, 1, 1, 0), add);
                            }
                            else
                            {
                                char add[12] = {0};
                                if (imm9)
                                    snprintf(add, 12, ", %s", imm(imm9, context, 1));

                                const char *instruction;
                                bool sf = 0;

                                switch (size)
                                {
                                    case 0b00:
                                    {
                                        if (unscaled)
                                        {
                                            instruction = "ldursb";
                                            sf = !variant;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldurb" : "sturb";
                                        }

                                        break;
                                    }

                                    case 0b01:
                                    {
                                        if (unscaled)
                                        {
                                            instruction = "ldursh";
                                            sf = !variant;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldurh" : "sturh";
                                        }
                                        
                                        break;
                                    }

                                    case 0b10:
                                    {
                                        if (unscaled)
                                        {
                                            if (variant)
                                                return;

                                            instruction = "ldursw";
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldurw" : "sturw";
                                        }
                                        
                                        break;
                                    }
                                    
                                    case 0b11:
                                    {
                                        if (unscaled)
                                        {
                                            char prefetch[24] = {0};
                                            decode_prefetch(rt, prefetch);
                                            snprintf(context->decode_string, 512, "prfum %s, [%s%s]", prefetch, reg(rn, 1, 1, 0), add);
                                            return;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldur" : "stur";
                                            sf = 1;
                                        }
                                        
                                        break;
                                    }
                                }

                                snprintf(context->decode_string, 512, "%s %s, [%s%s]", instruction, reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), add);
                            }

                            break;
                        }
                    
                        case 0b01:
                        {
                            uint8_t size = masks(instruction, 0b11, 30);
                            bool V = masks(instruction, 0b1, 26);
                            uint8_t opc = masks(instruction, 0b11, 22);
                            int16_t imm9 = sign_extend(masks(instruction, 0b111111111, 12), 9);
                            uint8_t rn = masks(instruction, 0b11111, 5);
                            uint8_t rt = mask(instruction, 0b11111);

                            bool unscaled = opc >> 1;
                            bool variant = opc & 1;

                            if (V)
                            {
                                uint8_t bits;

                                if (unscaled)
                                {
                                    if (size == 0b00)
                                        bits = 128;
                                    else
                                        return;
                                }
                                else
                                {
                                    bits = 8 << size;
                                }

                                char add[12] = {0};
                                if (imm9)
                                    snprintf(add, 12, ", %s", imm(imm9, context, 1));

                                snprintf(context->decode_string, 512, "%s %s, [%s%s]", variant ? "ldr" : "str", reg(rt, 0, bits, 1), reg(rn, 1, 1, 0), add);
                            }
                            else
                            {
                                char add[12] = {0};
                                if (imm9)
                                    snprintf(add, 12, ", %s", imm(imm9, context, 1));

                                const char *instruction;
                                bool sf = 0;

                                switch (size)
                                {
                                    case 0b00:
                                    {
                                        if (unscaled)
                                        {
                                            instruction = "ldrsb";
                                            sf = !variant;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldrb" : "strb";
                                        }

                                        break;
                                    }

                                    case 0b01:
                                    {
                                        if (unscaled)
                                        {
                                            instruction = "ldrsh";
                                            sf = !variant;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldrh" : "strh";
                                        }
                                        
                                        break;
                                    }

                                    case 0b10:
                                    {
                                        if (unscaled)
                                        {
                                            if (variant)
                                                return;

                                            instruction = "ldrsw";
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldr" : "str";
                                        }
                                        
                                        break;
                                    }
                                    
                                    case 0b11:
                                    {
                                        if (unscaled)
                                        {
                                            return;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldr" : "str";
                                            sf = 1;
                                        }
                                        
                                        break;
                                    }
                                }

                                snprintf(context->decode_string, 512, "%s %s, [%s]%s", instruction, reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), add);
                            }

                            break;
                        }
                    
                        case 0b10:
                        {
                            uint8_t size = masks(instruction, 0b11, 30);
                            bool V = masks(instruction, 0b1, 26);
                            uint8_t opc = masks(instruction, 0b11, 22);
                            int16_t imm9 = sign_extend(masks(instruction, 0b111111111, 12), 9);
                            uint8_t rn = masks(instruction, 0b11111, 5);
                            uint8_t rt = mask(instruction, 0b11111);

                            bool unscaled = opc >> 1;
                            bool variant = opc & 1;

                            if (V)
                                return;
                            
                            char add[12] = {0};
                            if (imm9)
                                snprintf(add, 12, ", %s", imm(imm9, context, 1));

                            const char *instruction;
                            bool sf = 0;

                            switch (size)
                            {
                                case 0b00:
                                {
                                    if (unscaled)
                                    {
                                        instruction = "ldtrsb";
                                        sf = !variant;
                                    }
                                    else
                                    {
                                        instruction = variant ? "ldtrb" : "sttrb";
                                    }

                                    break;
                                }

                                case 0b01:
                                {
                                    if (unscaled)
                                    {
                                        instruction = "ldtrsh";
                                        sf = !variant;
                                    }
                                    else
                                    {
                                        instruction = variant ? "ldtrh" : "sttrh";
                                    }
                                    
                                    break;
                                }

                                case 0b10:
                                {
                                    if (unscaled)
                                    {
                                        if (variant)
                                            return;

                                        instruction = "ldtrsw";
                                    }
                                    else
                                    {
                                        instruction = variant ? "ldtr" : "sttr";
                                    }
                                    
                                    break;
                                }
                                
                                case 0b11:
                                {
                                    if (unscaled)
                                    {
                                        return;
                                    }
                                    else
                                    {
                                        instruction = variant ? "ldtr" : "sttr";
                                        sf = 1;
                                    }
                                    
                                    break;
                                }
                            }

                            snprintf(context->decode_string, 512, "%s %s, [%s%s]", instruction, reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), add);
                            break;
                        }
                    
                        case 0b11:
                        {
                            uint8_t size = masks(instruction, 0b11, 30);
                            bool V = masks(instruction, 0b1, 26);
                            uint8_t opc = masks(instruction, 0b11, 22);
                            int16_t imm9 = sign_extend(masks(instruction, 0b111111111, 12), 9);
                            uint8_t rn = masks(instruction, 0b11111, 5);
                            uint8_t rt = mask(instruction, 0b11111);

                            bool unscaled = opc >> 1;
                            bool variant = opc & 1;

                            if (V)
                            {
                                uint8_t bits;

                                if (unscaled)
                                {
                                    if (size == 0b00)
                                        bits = 128;
                                    else
                                        return;
                                }
                                else
                                {
                                    bits = 8 << size;
                                }

                                char add[12] = {0};
                                if (imm9)
                                    snprintf(add, 12, ", %s", imm(imm9, context, 1));

                                snprintf(context->decode_string, 512, "%s %s, [%s%s]", variant ? "ldr" : "str", reg(rt, 0, bits, 1), reg(rn, 1, 1, 0), add);
                            }
                            else
                            {
                                char add[12] = {0};
                                if (imm9)
                                    snprintf(add, 12, ", %s", imm(imm9, context, 1));

                                const char *instruction;
                                bool sf = 0;

                                switch (size)
                                {
                                    case 0b00:
                                    {
                                        if (unscaled)
                                        {
                                            instruction = "ldrsb";
                                            sf = !variant;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldrb" : "strb";
                                        }

                                        break;
                                    }

                                    case 0b01:
                                    {
                                        if (unscaled)
                                        {
                                            instruction = "ldrsh";
                                            sf = !variant;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldrh" : "strh";
                                        }
                                        
                                        break;
                                    }

                                    case 0b10:
                                    {
                                        if (unscaled)
                                        {
                                            if (variant)
                                                return;

                                            instruction = "ldrsw";
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldr" : "str";
                                        }
                                        
                                        break;
                                    }
                                    
                                    case 0b11:
                                    {
                                        if (unscaled)
                                        {
                                            return;
                                        }
                                        else
                                        {
                                            instruction = variant ? "ldr" : "str";
                                            sf = 1;
                                        }
                                        
                                        break;
                                    }
                                }

                                snprintf(context->decode_string, 512, "%s %s, [%s%s]!", instruction, reg(rt, 0, sf, 0), reg(rn, 1, 1, 0), add);
                            }

                            break;
                        }
                    }
                }
            }

            break;
        }
    }
}

void disassemble_data_register(decode_context_t *context)
{
    uint32_t instruction = context->instruction;
    
    bool op0 = masks(instruction, 0b1, 30);
    bool op1 = masks(instruction, 0b1, 28);
    uint8_t op2 = masks(instruction, 0b1111, 21);
    uint8_t op3 = masks(instruction, 0b111111, 10);

    bool sf = masks(instruction, 0b1, 31);
    uint8_t shift = masks(instruction, 0b11, 22);
    uint8_t rm = masks(instruction, 0b11111, 16);
    uint8_t imm6 = masks(instruction, 0b111111, 10);
    uint8_t rn = masks(instruction, 0b11111, 5);
    uint8_t rd = mask(instruction, 0b11111);

    if (op1)
    {
        if (op2 == 0b0110)
        {
            bool S = masks(instruction, 0b1, 29);

            if (op0)
            {
                if (S || !sf)
                    return;

                if (rm)
                {
                    // armv8.3

                    if (rm & 0b11110 || imm6 > 0b010001)
                        return;

                    bool Z = masks(imm6, 0b1, 3);

                    if (Z && rn != 0b11111)
                        return;

                    static const char *instructions[] = {"pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb", "paciza", "pacizb", "pacdza", "paczdb", "autiza", "autizb", "autdza", "autdzb", "xpaci", "xpacd"};
                    const char *instruction = instructions[imm6];

                    if (Z)
                        snprintf(context->decode_string, 512, "%s %s", instruction, reg(rd, 0, 1, 0));
                    else
                        snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, 1, 0), reg(rn, 1, 1, 0));
                }
                else
                {
                    if (!sf && imm6 == 0b000011)
                        return;

                    const char *instruction = NULL;

                    if (imm6 == 0b000010)
                    {
                        instruction = sf ? "rev32" : "rev";
                    }
                    else if (imm6 == 0b000011)
                    {
                        if (!sf)
                            return;

                        instruction = "rev";
                    }
                    else if (imm6 < 0b000110)
                    {
                        static const char *instructions[] = {"rbit", "rev16", NULL, NULL, "clz", "cls"};
                        instruction = instructions[imm6];
                    }

                    if (!instruction)
                        return;

                    snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, sf, 0), reg(rn, 0, sf, 0));
                }
            }
            else
            {
                const char *instruction = NULL;

                switch (imm6)
                {
                    case 0b000000:
                    {
                        if (!sf)
                            return;

                        if (S)
                        {
                            if (rd == 0b11111)
                                snprintf(context->decode_string, 512, "cmpp %s, %s", reg(rn, 1, 1, 0), reg(rm, 1, 1, 0));
                            else
                                snprintf(context->decode_string, 512, "subps %s, %s, %s", reg(rd, 0, 1, 0), reg(rn, 1, 1, 0), reg(rm, 1, 1, 0)); // armv8.5
                        }
                        else
                        {
                            // armv8.5
                            snprintf(context->decode_string, 512, "subp %s, %s, %s", reg(rd, 0, 1, 0), reg(rn, 1, 1, 0), reg(rm, 1, 1, 0));
                        }

                        return;
                    }

                    case 0b000100:
                    case 0b000101:
                    {
                        // armv8.5

                        if (!sf)
                            return;

                        bool gmi = (imm6 & 1);
                        const char *instruction = gmi ? "gmi" : "irg";

                        char add[16] = {0};
                        if (rm != 0b11111 || gmi)
                            snprintf(context->decode_string, 15, ", %s", reg(rm, 0, 1, 0));
                        
                        snprintf(context->decode_string, 512, "%s %s, %s%s", instruction, reg(rd, !gmi, 1, 0), reg(rn, 1, 1, 0), add);
                        return;
                    }

                    case 0b001100:
                    {
                        // armv8.3

                        if (S || !sf)
                            return;

                        snprintf(context->decode_string, 512, "pacga %s, %s, %s", reg(rd, 0, 1, 0), reg(rn, 0, 1, 0), reg(rm, 1, 1, 0));
                        return;
                    }

                    case 0b010011:
                    {
                        if (!sf)
                            return;

                        instruction = "crc32x";
                        break;
                    }

                    case 0b010111:
                    {
                        if (!sf)
                            return;

                        instruction = "crc32cx";
                        break;
                    }

                    case 0b010000:
                    {
                        if (sf)
                            return;

                        instruction = "crc32b";
                        break;
                    }

                    case 0b010001:
                    {
                        if (sf)
                            return;

                        instruction = "crc32h";
                        break;
                    }

                    case 0b010010:
                    {
                        if (sf)
                            return;

                        instruction = "crc32w";
                        break;
                    }

                    case 0b010100:
                    {
                        if (sf)
                            return;

                        instruction = "crc32cb";
                        break;
                    }

                    case 0b010101:
                    {
                        if (sf)
                            return;

                        instruction = "crc32ch";
                        break;
                    }

                    case 0b010110:
                    {
                        if (sf)
                            return;

                        instruction = "crc32cw";
                        break;
                    }

                    case 0b000010: instruction = "udiv"; break;
                    case 0b000011: instruction = "sdiv"; break;
                    case 0b001000: instruction = "lsl"; break;
                    case 0b001001: instruction = "lsr"; break;
                    case 0b001010: instruction = "asr"; break;
                    case 0b001011: instruction = "ror"; break;
                }
            
                snprintf(context->decode_string, 512, "%s %s, %s, %s", instruction, reg(rd, 0, sf, 0), reg(rn, 0, 1, 0), reg(rm, 0, 1, 0));
            }
        }
        else if (!op2)
        {
            if (!op3)
            {
                bool S = masks(instruction, 0b1, 29);
                uint8_t op = (op0 << 1) | S;

                static const char *instructions[] = {"adc", "adcs", "sbc", "sbcs"};

                if (op0 && rn == 0b11111)
                {
                    const char *instruction = S ? "ngcs" : "ngc";
                    snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, sf, 0), reg(rm, 0, sf, 0));
                    return;
                }

                snprintf(context->decode_string, 512, "%s %s, %s, %s", instructions[op], reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), reg(rm, 0, sf, 0));
            }
            else if ((op3 & 0b11111) == 0b00001)
            {
                bool S = masks(instruction, 0b1, 29);
                uint8_t imm6 = masks(instruction, 0b111111, 15);
                bool o2 = masks(instruction, 0b1, 4);
                uint8_t mask = mask(instruction, 0b1111);

                if (sf && !op0 && S && !o2)
                {
                    // armv8.4
                    snprintf(context->decode_string, 512, "rmif %s, %s, %s", reg(rn, 0, 1, 0), imm(shift, context, 0), imm(mask, context, 0));
                }
            }
            else if ((op3 & 0b1111) == 0b0010)
            {
                bool S = masks(instruction, 0b1, 29);
                uint8_t opcode2 = masks(instruction, 0b111111, 15);
                bool sz = masks(instruction, 0b1, 14);
                bool o3 = masks(instruction, 0b1, 4);
                uint8_t mask = mask(instruction, 0b1111);

                if (mask == 0b1101 && !o3 && !opcode2 && !sf && !op0 && S)
                {
                    // armv8.4

                    const char *instruction = sz ? "setf16" : "setf8";
                    snprintf(context->decode_string, 512, "%s %s", instruction, reg(rn, 0, 1, 0));
                }
            }
        }
        else if (op2 == 0b0010)
        {
            bool S = masks(instruction, 0b1, 29);
            uint8_t cond = masks(instruction, 0b1111, 12);
            bool o2 = masks(instruction, 0b1, 10);
            bool o3 = masks(instruction, 0b1, 4);
            uint8_t nzcv = mask(instruction, 0b1111);

            if (!S || o2 || o3)
                return;

            const char *instruction = op0 ? "ccmp" : "ccmn";
            char *arg2 = (op3 & 0b10) ? imm(rm, context, 0) : reg(rm, 0, sf, 0);
            snprintf(context->decode_string, 512, "%s %s, %s, %s, %s", instruction, reg(rn, 0, sf, 0), arg2, imm(nzcv, context, 0), decode_condition(cond));
        }
        else if (op2 == 0b0100)
        {
            bool S = masks(instruction, 0b1, 29);
            uint8_t cond = masks(instruction, 0b1111, 12);
            uint8_t op2 = masks(instruction, 0b11, 10);
            
            if (S || (op2 & 0b10))
                return;

            uint8_t op = (op0 << 1) | op2;

            switch (op)
            {
                case 0b01:
                {
                    if (rm != 0b11111 && (cond & 0b1110) != 0b1110 && rn != 0b11111 && rn == rm)
                    {
                        snprintf(context->decode_string, 512, "cinc %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), decode_condition(cond ^ 1));
                        return;
                    }
                    else if (rm == 0b11111 && (cond & 0b1110) != 0b1110 && rn == 0b11111)
                    {
                        snprintf(context->decode_string, 512, "cset %s, %s", reg(rd, 0, sf, 0), decode_condition(cond ^ 1));
                        return;
                    }
                    break;
                }

                case 0b10:
                {
                    if (rm != 0b11111 && (cond & 0b1110) != 0b1110 && rn != 0b11111 && rn == rm)
                    {
                        snprintf(context->decode_string, 512, "cinv %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), decode_condition(cond ^ 1));
                        return;
                    }
                    else if (rm == 0b11111 && (cond & 0b1110) != 0b1110 && rn == 0b11111)
                    {
                        snprintf(context->decode_string, 512, "csetm %s, %s", reg(rd, 0, sf, 0), decode_condition(cond ^ 1));
                        return;
                    }
                    break;
                }

                case 0b11:
                {
                    if ((cond & 0b1110) != 0b1110 && rn == rm)
                    {
                        snprintf(context->decode_string, 512, "cneg %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), decode_condition(cond ^ 1));
                        return;
                    }

                    break;
                }
            }

            static const char *instructions[] = {"csel", "csinc", "csinv", "csneg"};
            snprintf(context->decode_string, 512, "%s %s, %s, %s, %s", instructions[op], reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), reg(rm, 0, sf, 0), decode_condition(cond));
        }
        else if (op2 >> 3)
        {
            uint8_t op54 = masks(instruction, 0b11, 29);
            uint8_t op31 = masks(instruction, 0b111, 21);
            bool o0 = masks(instruction, 0b1, 15);
            uint8_t ra = masks(instruction, 0b11111, 10);

            if (op54 || (op31 && !sf))
                return;

            uint8_t opc = (op31 << 1) | o0;
            const char *instruction;

            bool middle_sf = !((opc >> 1) & 1);

            if (!(opc >> 1))
                middle_sf = sf;

            if (ra == 0b11111)
            {
                switch (opc)
                {
                    case 0b0000: instruction = "mul"; break;
                    case 0b0001: instruction = "mneg"; break;
                    case 0b0010: instruction = "smull"; break;
                    case 0b0011: instruction = "smnegl"; break;
                    case 0b0100: instruction = ""; break;
                    case 0b1010: instruction = "umull"; break;
                    case 0b1011: instruction = "umnegl"; break;
                    default: return;

                    case 0b1100:
                    {
                        if (ra != 0b11111)
                            return;
                        
                        snprintf(context->decode_string, 512, "umulh %s, %s, %s", reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), reg(rm, 0, sf, 0));
                        return;
                    }
                }

                if (*instruction)
                {
                    snprintf(context->decode_string, 512, "%s %s, %s, %s", instruction, reg(rd, 0, sf, 0), reg(rn, 0, middle_sf, 0), reg(rm, 0, middle_sf, 0));
                    return;
                }
            }
            
            switch (opc)
            {
                case 0b0000: instruction = "madd"; break;
                case 0b0001: instruction = "msub"; break;
                case 0b0010: instruction = "smaddl"; break;
                case 0b0011: instruction = "smsubl"; break;
                case 0b0100: instruction = "smulh"; break;
                case 0b1010: instruction = "umaddl"; break;
                case 0b1011: instruction = "umsubl"; break;
                default: return;
            }

            snprintf(context->decode_string, 512, "%s %s, %s, %s, %s", instruction, reg(rd, 0, sf, 0), reg(rn, 0, middle_sf, 0), reg(rm, 0, middle_sf, 0), reg(ra, 0, sf, 0));
        }
    }
    else
    {
        if (op2 & 0b1000)
        {
            static const char *instructions[] = {"add", "adds", "sub", "subs"};
            bool op = masks(instruction, 0b1, 30);
            bool S = masks(instruction, 0b1, 29);

            if (op2 & 0b1)
            {
                uint8_t option = masks(instruction, 0b111, 13);
                uint8_t imm3 = masks(instruction, 0b111, 10);

                if (shift || (imm3 & 0b101) == 0b101 || (imm3 & 0b110) == 0b110)
                    return;

                char add[16] = {0};
                if (imm3)
                    snprintf(add, 15, ", %s %s", decode_extend(option), imm(imm3, context, 0));

                uint8_t opc = (op << 1) | S;
                bool rm_bits = sf ? ((option & 0b011) ? 1 : 0) : 0;

                switch (opc)
                {
                    case 0b01:
                    {
                        if (rd == 0b11111)
                        {
                            snprintf(context->decode_string, 512, "cmn %s, %s%s", reg(rn, 1, sf, 0), reg(rm, 0, rm_bits, 0), add);
                            return;
                        }

                        break;
                    }

                    case 0b11:
                    {
                        if (rd == 0b11111)
                        {
                            snprintf(context->decode_string, 512, "cmp %s, %s%s", reg(rn, 1, sf, 0), reg(rm, 0, rm_bits, 0), add);
                            return;
                        }

                        break;
                    }
                }

                snprintf(context->decode_string, 512, "%s %s, %s, %s%s", instructions[opc], reg(rd, !S, sf, 0), reg(rn, 1, sf, 0), reg(rm, 0, rm_bits, 0), add);
            }
            else
            {
                if (shift == 0b11 || ((imm6 >> 5) && !sf))
                    return;

                char add[16] = {0};
                if (imm6)
                    snprintf(add, 15, ", %s %s", decode_shift(shift), imm(imm6, context, 0));

                uint8_t opc = (op << 1) | S;

                switch (opc)
                {
                    case 0b01:
                    {
                        if (rd == 0b11111)
                        {
                            snprintf(context->decode_string, 512, "cmn %s, %s%s", reg(rn, 0, sf, 0), reg(rm, 0, sf, 0), add);
                            return;
                        }

                        break;
                    }

                    case 0b10:
                    {
                        if (rn == 0b11111)
                        {
                            snprintf(context->decode_string, 512, "neg %s, %s%s", reg(rd, 0, sf, 0), reg(rm, 0, sf, 0), add);
                            return;
                        }

                        break;
                    }

                    case 0b11:
                    {
                        if (rd == 0b11111)
                        {
                            snprintf(context->decode_string, 512, "cmp %s, %s%s", reg(rn, 0, sf, 0), reg(rm, 0, sf, 0), add);
                            return;
                        }
                        else if (rn == 0b11111)
                        {
                            snprintf(context->decode_string, 512, "cmp %s, %s%s", reg(rd, 0, sf, 0), reg(rm, 0, sf, 0), add);
                            return;
                        }

                        break;
                    }
                }

                snprintf(context->decode_string, 512, "%s %s, %s, %s%s", instructions[opc], reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), reg(rm, 0, sf, 0), add);
            }
        }
        else
        {
            uint8_t opc = masks(instruction, 0b11, 29);
            bool N = masks(instruction, 0b1, 21);

            if (!sf && (imm6 & 0b100000))
                return;

            uint8_t op = (opc << 1) | N;

            if (op == 0b010 && !shift && !imm6 && rn == 0b11111)
            {
                snprintf(context->decode_string, 512, "mov %s, %s", reg(rd, 0, sf, 0), reg(rm, 0, sf, 0));
                return;
            }

            char add[16] = {0};
            if (imm6)
                snprintf(add, 16, ", %s %s", decode_shift(shift), imm(imm6, context, 0));

            if (op == 0b011 && rn == 0b11111)
            {
                snprintf(context->decode_string, 512, "mvn %s, %s%s", reg(rd, 0, sf, 0), reg(rm, 0, sf, 0), add);
                return;
            }

            if (op == 0b110 && rd == 0b11111)
            {
                snprintf(context->decode_string, 512, "tst %s, %s%s", reg(rn, 0, sf, 0), reg(rm, 0, sf, 0), add);
                return;
            }

            static const char *instructions[] = {"and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"};
            snprintf(context->decode_string, 512, "%s %s, %s, %s%s", instructions[op], reg(rd, 0, sf, 0), reg(rn, 0, sf, 0), reg(rm, 0, sf, 0), add);
        }
    }
}

void disassemble_data_float(decode_context_t *context)
{
    uint32_t instruction = context->instruction;

    uint8_t op0 = masks(instruction, 0b1111, 28);
    uint8_t op1 = masks(instruction, 0b11, 23);
    uint8_t op2 = masks(instruction, 0b1111, 19);
    uint16_t op3 = masks(instruction, 0b111111111, 10);

    if (op0 == 0b0100 && !(op1 >> 1) && (op2 & 0b0111) == 0b0101 && (op3 & 0b110000011) == 0b000000010)
    {
        // cryptographic AES

        uint8_t size = masks(instruction, 0b11, 22);
        uint8_t opcode = masks(instruction, 0b11111, 12);
        uint8_t rn = masks(instruction, 0b11111, 5);
        uint8_t rd = mask(instruction, 0b11111);

        if (size)
            return;

        const char *instruction;

        switch (opcode)
        {
            case 0b00100: instruction = "aese"; break;
            case 0b00101: instruction = "aesd"; break;
            case 0b00110: instruction = "aesmd"; break;
            case 0b00111: instruction = "aesimc"; break;
            default: return;
        }

        snprintf(context->decode_string, 512, "%s %s.16b, %s.16b", instruction, sreg[rd], sreg[rn]);
    }
    else if (op0 == 0b0101 && !(op1 >> 1) && !(op2 & 0b0100) && !(op3 & 0b000100011))
    {
        // cryptographic three-register SHA

        uint8_t size = masks(instruction, 0b11, 22);
        uint8_t rm = masks(instruction, 0b11111, 16);
        uint8_t opcode = masks(instruction, 0b111, 12);
        uint8_t rn = masks(instruction, 0b11111, 5);
        uint8_t rd = mask(instruction, 0b11111);

        if (size || opcode == 0b111)
            return;

        static const char *instructions[] = {"sha1c", "sha1p", "sha1m", "sha1su0", "sha256h", "sha256h2", "sha256su1"};
        const char *instruction = instructions[opcode];

        if (opcode == 0b011 || opcode == 0b110)
        {
            snprintf(context->decode_string, 512, "%s %s.4s, %s.4s, %s.4s", instruction, sreg[rd], sreg[rn], sreg[rm]);
            return;
        }

        uint8_t bits = (opcode & 0b100) ? 128 : 32;

        snprintf(context->decode_string, 512, "%s %s, %s, %s.4s", instruction, reg(rd, 0, 128, 1), reg(rn, 0, bits, 1), sreg[rm]);
    }
    else if (op0 == 0b0101 && !(op1 >> 1) && (op2 & 0b0111) == 0b0101 && (op3 & 0b110000011) == 0b000000010)
    {
        // cryptographic two-register SHA

        uint8_t size = masks(instruction, 0b11, 22);
        uint8_t opcode = masks(instruction, 0b11111, 12);
        uint8_t rn = masks(instruction, 0b11111, 5);
        uint8_t rd = mask(instruction, 0b11111);

        if (size || opcode > 0b00010)
            return;

        if (!opcode)
            snprintf(context->decode_string, 512, "sha1h %s, %s", reg(rd, 0, 32, 1), reg(rn, 0, 32, 1));
        else
            snprintf(context->decode_string, 512, "%s %s.4s, %s.4s", (opcode >> 1) ? "sha256su0" : "sha1su1", sreg[rd], sreg[rn]);
    }
    else if ((op0 & 0b1101) == 0b0101)
    {
        if (!(op1 >> 1))
        {
            if ((op2 & 0b1100) == 0b1000 && (op3 & 0b000110001) == 0b000000001)
            {
                // advanced SIMD scalar three same FP16
                // armv8.2

                bool U = masks(instruction, 0b1, 29);
                bool a = masks(instruction, 0b1, 23);
                uint8_t rm = masks(instruction, 0b11111, 16);
                uint8_t opcode = masks(instruction, 0b111, 11);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t rd = mask(instruction, 0b11111);

                const char *instruction;

                switch ((U << 4) | (a << 3) | opcode)
                {
                    case 0b00011: instruction = "fmulx"; break;
                    case 0b00100: instruction = "fcmeq"; break;
                    case 0b00111: instruction = "frecps"; break;
                    case 0b01111: instruction = "frsqrts"; break;
                    case 0b10100: instruction = "fcmge"; break;
                    case 0b10101: instruction = "facge"; break;
                    case 0b11010: instruction = "fabd"; break;
                    case 0b11100: instruction = "fcmgt"; break;
                    case 0b11101: instruction = "facgt"; break;
                    default: return;
                }

                snprintf(context->decode_string, 512, "%s %s, %s, %s", instruction, reg(rd, 0, 16, 1), reg(rn, 0, 16, 1), reg(rm, 0, 16, 1));
            }
            else if (op2 == 0b1111 && (op3 & 0b110000011) == 0b000000010)
            {
                // advanced SIMD scalar two-register miscellaneous FP16
                // armv8.2

                // bool U = masks(instruction, 0b1, 29);
                // bool a = masks(instruction, 0b1, 23);
                // uint8_t opcode = masks(instruction, 0b11111, 12);
                // uint8_t rn = masks(instruction, 0b11111, 5);
                // uint8_t rd = mask(instruction, 0b11111);
            }
            else if (!(op2 & 0b0100) && (op3 & 0b000100001) == 0b000100001)
            {
                // advanced SIMD scalar three same extra
                // armv8.1

                bool Q = masks(instruction, 0b1, 30);
                bool U = masks(instruction, 0b1, 29);
                uint8_t size = masks(instruction, 0b11, 22);
                uint8_t rm = masks(instruction, 0b11111, 16);
                uint8_t opcode = masks(instruction, 0b1111, 11);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t rd = mask(instruction, 0b11111);

                if (!U || opcode & 0b1110)
                    return;

                const char *specifier;

                switch ((size << 1) | Q)
                {
                    case 0b010: specifier = "4h"; break;
                    case 0b011: specifier = "8h"; break;
                    case 0b100: specifier = "2s"; break;
                    case 0b101: specifier = "4s"; break;
                    default: return;
                }

                snprintf(context->decode_string, 512, "%s %s.%s, %s.%s, %s.%s", opcode ? "sqrdmlsh" : "sqrdmlah", sreg[rd], specifier, sreg[rn], specifier, sreg[rm], specifier);
            }
            else if ((op2 & 0b0111) == 0b0100 && (op3 & 0b110000011) == 0b000000010)
            {
                // advanced SIMD scalar two-register miscellaneous
            }
            else if ((op2 & 0b0111) == 0b0110 && (op3 & 0b110000011) == 0b000000010)
            {
                // advanced SIMD scalar pairwise
            }
            else if ((op2 & 0b0100) == 0b0100 && !(op3 & 0b000000011))
            {
                // advanced SIMD scalar three different

                bool U = masks(instruction, 0b1, 29);
                uint8_t size = masks(instruction, 0b11, 22);
                uint8_t rm = masks(instruction, 0b11111, 16);
                uint8_t opcode = masks(instruction, 0b1111, 12);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t rd = mask(instruction, 0b11111);

                if (U)
                    return;

                const char *instruction;
                const char *ta, *tb;

                switch (opcode)
                {
                    case 0b1001: instruction = "sqdmlal2"; break;
                    case 0b1011: instruction = "sqdmlsl2"; break;
                    case 0b1101: instruction = "sqdmull2"; break;
                    default: return;
                }

                switch (size)
                {
                    case 0b01: ta = "4s"; tb = "8h"; break;
                    case 0b10: ta = "2d"; tb = "4s"; break;
                    default: return;
                }

                snprintf(context->decode_string, 512, "%s %s.%s, %s.%s, %s.%s", instruction, sreg[rd], ta, sreg[rn], tb, sreg[rm], tb);
            }
            else if ((op2 & 0b0100) == 0b0100 && (op3 & 0b000000001) == 0b000000001)
            {
                // advanced SIMD scalar three same
            }
        }

        if (!op1 && !(op2 & 0b1100) && (op3 & 0b000100001) == 0b000000001)
        {
            // advanced SIMD scalar copy
        }
        else if (op1 == 0b10 && (op3 & 0b000000001) == 0b000000001)
        {
            // advanced SIMD scalar shift
        }
        else if ((op1 >> 1) && (op3 & 0b000000001) == 0b000000001)
        {
            // advanced SIMD scalar x indexed element
        }
    }
    else if (!(op0 & 0b1011) && !(op1 >> 1) && !(op2 & 0b0100) && !(op3 & 0b000100011))
    {
        // advanced SIMD table lookup
    }
    else if (!(op0 & 0b1011) && !(op1 >> 1) && !(op2 & 0b0100) && (op3 & 0b000100011) == 0b000000010)
    {
        // advanced SIMD permute
    }
    else if ((op0 & 0b1011) == 0b0010 && !(op1 >> 1) && !(op2 & 0b0100) && !(op3 & 0b000100001))
    {
        // advanced SIMD extract
    }
    else if (!(op0 & 0b1001))
    {
        if (!op1 && !(op2 & 0b1100) && (op3 & 0b000100001) == 0b000000001)
        {
            // advanced SIMD copy

            // bool Q = masks(instruction, 0b1, 30);
            // bool op = masks(instruction, 0b1, 29);
            // uint8_t imm5 = masks(instruction, 0b11111, 16);
            // uint8_t imm4 = masks(instruction, 0b1111, 11);
            // uint8_t rn = masks(instruction, 0b11111, 5);
            // uint8_t rd = mask(instruction, 0b11111);
        }
        else if (!(op1 >> 1))
        {
            if ((op2 & 0b1100) == 0b1000 && (op3 & 0b000110001) == 0b000000001)
            {
                // advanced SIMD three same (FP16)
            }
            else if (op2 == 0b1111 && (op3 & 0b110000011) == 0b000000010)
            {
                // advanced SIMD two-register miscellaneous (FP16)
            }
            else if (!(op2 & 0b0100) && (op3 & 0b000100001) == 0b000100001)
            {
                // advanced SIMD three same extra
            }
            else if ((op2 & 0b0111) == 0b0100 && (op3 & 0b110000010) == 0b000000010)
            {
                // advanced SIMD two-register miscellaneous
            }
            else if ((op2 & 0b0111) == 0b0110 && (op3 & 0b110000010) == 0b000000010)
            {
                // advanced SIMD across lanes
            }
            else if ((op2 & 0b0100) == 0b0100 && !(op3 & 0b000000011))
            {
                // advanced SIMD three different
            }
            else if ((op2 & 0b0100) == 0b0100 && (op3 & 0b000000001) == 0b000000001)
            {
                // advanced SIMD three same
            }
        }
        else if (op1 >> 1)
        {
            if (!(op1 & 0b01))
            {
                if ((op3 & 0b000000001) == 0b000000001)
                {
                    if (op2)
                    {
                        // advanced SIMD shift by immediate
                    }
                    else
                    {
                        // advanced SIMD modified immediate
                    }
                }
            }

            if (!(op3 & 0b000000001))
            {
                // advanced SIMD vector x indexed element
            }
        }
    }
    else if (op0 == 0b1100)
    {
        if (op1 == 0b00)
        {
            if ((op3 & 0b000100000))
            {
                if ((op2 & 0b1100) == 0b1000 && (op3 & 0b000110000) == 0b000100000)
                {
                    // cryptographic three-register, imm2
                }
                else if ((op2 & 0b1100) == 0b1100 && (op3 & 0b000101100) == 0b000100000)
                {
                    // cryptographic three-register sha 512
                }
            }
            else
            {
                // cryptographic 4 register
            }
        }
        else if (op1 == 0b01)
        {
            if (!(op2 & 0b1100))
            {
                // xar
                // armv8.2

                uint8_t rm = masks(instruction, 0b11111, 16);
                uint8_t imm6 = masks(instruction, 0b111111, 10);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t rd = mask(instruction, 0b11111);

                snprintf(context->decode_string, 512, "xar %s.2d, %s.2d, %s.2d, %s", sreg[rd], sreg[rn], sreg[rm], imm(imm6, context, 0));
            }
            else if (op2 == 0b1000 && (op3 & 0b111111100) == 0b000100000)
            {
                // cryptographic two-register sha 512
            }
        }
    }
    else if ((op0 & 0b0101) == 0b0001)
    {
        if (op1 >> 1)
        {
            // floating-point data-processing (3 source)

            bool M = masks(instruction, 0b1, 31);
            bool S = masks(instruction, 0b1, 29);
            uint8_t ptype = masks(instruction, 0b11, 22);
            bool o1 = masks(instruction, 0b1, 21);
            uint8_t rm = masks(instruction, 0b11111, 16);
            bool o0 = masks(instruction, 0b1, 15);
            uint8_t ra = masks(instruction, 0b11111, 10);
            uint8_t rn = masks(instruction, 0b11111, 5);
            uint8_t rd = mask(instruction, 0b11111);

            uint8_t bits;

            switch (ptype)
            {
                case 0b00: bits = 32; break;
                case 0b01: bits = 64; break;
                case 0b11: bits = 16; break; // armv8.2
                default: return;
            }

            static const char *instructions[] = {"fmadd", "fmsub", "fnmadd", "fnmsub"};
            const char *instruction = instructions[(o1 << 1) | o0];

            snprintf(context->decode_string, 512, "%s %s, %s, %s, %s", instruction, reg(rd, 0, bits, 1), reg(rn, 0, bits, 1), reg(rm, 0, bits, 1), reg(ra, 0, bits, 1));
        }
        else
        {
            if (op2 & 0b0100)
            {
                if (!(op3 & 0b000111111))
                {
                    // conversion between floating-point and integer

                    bool sf = masks(instruction, 0b1, 31);
                    bool S = masks(instruction, 0b1, 29);
                    uint8_t ptype = masks(instruction, 0b11, 22);
                    uint8_t rmode = masks(instruction, 0b11, 19);
                    uint8_t opcode = masks(instruction, 0b111, 16);
                    uint8_t rn = masks(instruction, 0b11111, 5);
                    uint8_t rd = mask(instruction, 0b11111);

                    if (S)
                        return;

                    if (sf)
                    {
                        switch (ptype)
                        {
                            case 0b00:
                            {
                                const char *instruction;
                                bool simd_first = 0;
                                
                                uint8_t op = (rmode << 3) | opcode;

                                switch (opcode)
                                {
                                    case 0b00000: instruction = "fcvtns"; break;
                                    case 0b00001: instruction = "fcvtnu"; break;
                                    case 0b00010: instruction = "scvtf"; simd_first = 1; break;
                                    case 0b00011: instruction = "ucvtf"; simd_first = 1; break;
                                    case 0b00100: instruction = "fcvtas"; break;
                                    case 0b00101: instruction = "fcvtau"; break;
                                    case 0b01000: instruction = "fcvtps"; break;
                                    case 0b01001: instruction = "fcvtpu"; break;
                                    case 0b10000: instruction = "fcvtms"; break;
                                    case 0b10001: instruction = "fcvtmu"; break;
                                    case 0b11000: instruction = "fcvtzs"; break;
                                    case 0b11001: instruction = "fcvtzu"; break;
                                }

                                snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, simd_first ? 32 : 64, simd_first), reg(rn, 0, simd_first ? 64 : 32, !simd_first));
                                break;
                            }

                            case 0b01:
                            {
                                const char *instruction;
                                bool simd_first;

                                if (rmode >> 1)
                                {
                                    uint8_t op = ((rmode & 1) << 1) | (opcode & 1);

                                    if (op > 0b11)
                                        return;

                                    static const char *instructions[] = {"fcvtms", "fcvtmu", "fcvtzs", "fcvtzu"};
                                    instruction = instructions[op];
                                }
                                else
                                {
                                    uint8_t op = (rmode << 3) | opcode;

                                    if (op > 0b1001)
                                        return;

                                    static const char *instructions[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov", "fcvtps", "fcvtpu"};
                                    instruction = instructions[op];

                                    if (op == 0b00010 || op == 0b00011 || op == 0b00111)
                                        simd_first = 1;
                                }

                                snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, 64, simd_first), reg(rn, 0, 64, !simd_first));
                                break;
                            }

                            case 0b11:
                            {
                                // armv8.2

                                const char *instruction;
                                bool simd_first = 0;

                                if (rmode >> 1)
                                {
                                    uint8_t op = ((rmode & 1) << 1) | (opcode & 1);

                                    if (op > 0b11)
                                        return;

                                    static const char *instructions[] = {"fcvtms", "fcvtmu", "fcvtzs", "fcvtzu"};
                                    instruction = instructions[op];
                                }
                                else
                                {
                                    uint8_t op = (rmode << 3) | opcode;

                                    if (op > 0b1001)
                                        return;

                                    static const char *instructions[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov", "fcvtps", "fcvtpu"};
                                    instruction = instructions[op];

                                    if (op == 0b00010 || op == 0b00011 || op == 0b00111)
                                        simd_first = 1;
                                }

                                snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, simd_first ? 16 : 64, simd_first), reg(rn, 0, simd_first ? 64 : 16, !simd_first));
                                break;
                            }
                        }
                    }
                    else
                    {
                        switch (ptype)
                        {
                            case 0b00:
                            {
                                const char *instruction;
                                bool simd_first = 0;

                                if (rmode >> 1)
                                {
                                    uint8_t op = ((rmode & 1) << 1) | (opcode & 1);

                                    if (op > 0b11)
                                        return;

                                    static const char *instructions[] = {"fcvtms", "fcvtmu", "fcvtzs", "fcvtzu"};
                                    instruction = instructions[op];
                                }
                                else
                                {
                                    uint8_t op = (rmode << 3) | opcode;

                                    if (op > 0b1001)
                                        return;

                                    static const char *instructions[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov", "fcvtps", "fcvtpu"};
                                    instruction = instructions[op];

                                    if (op == 0b00010 || op == 0b00011 || op == 0b00111)
                                        simd_first = 1;
                                }

                                snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, 32, simd_first), reg(rn, 0, 32, !simd_first));
                                break;
                            }

                            case 0b01:
                            {
                                const char *instruction;
                                bool simd_first = 0;

                                uint8_t op = (rmode << 3) | opcode;

                                switch (op)
                                {
                                    case 0b00000: instruction = "fcvtns"; break;
                                    case 0b00001: instruction = "fcvtnu"; break;
                                    case 0b00010: instruction = "scvtf"; simd_first = 1; break;
                                    case 0b00011: instruction = "ucvtf"; simd_first = 1; break;
                                    case 0b00100: instruction = "fcvtas"; break;
                                    case 0b00101: instruction = "fcvtau"; break;
                                    case 0b01000: instruction = "fcvtps"; break;
                                    case 0b01001: instruction = "fcvtpu"; break;
                                    case 0b10000: instruction = "fcvtms"; break;
                                    case 0b10001: instruction = "fcvtmu"; break;
                                    case 0b11000: instruction = "fcvtzs"; break;
                                    case 0b11001: instruction = "fcvtzu"; break;
                                    default: return;
                                    
                                    case 0b10110:
                                    {
                                        // armv8.3
                                        snprintf(context->decode_string, 512, "fjcvtzs %s, %s", reg(rd, 0, 0, 0), reg(rn, 0, 64, 1));
                                        return;
                                    }
                                }

                                snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, simd_first ? 64 : 32, simd_first), reg(rn, 0, simd_first ? 32 : 64, !simd_first));
                                break;
                            }

                            case 0b11:
                            {
                                // armv8.2

                                const char *instruction;
                                bool simd_first = 0;

                                if (rmode >> 1)
                                {
                                    uint8_t op = ((rmode & 1) << 1) | (opcode & 1);

                                    if (op > 0b11)
                                        return;

                                    static const char *instructions[] = {"fcvtms", "fcvtmu", "fcvtzs", "fcvtzu"};
                                    instruction = instructions[op];
                                }
                                else
                                {
                                    uint8_t op = (rmode << 3) | opcode;

                                    if (op > 0b1001)
                                        return;

                                    static const char *instructions[] = {"fcvtns", "fcvtnu", "scvtf", "ucvtf", "fcvtas", "fcvtau", "fmov", "fmov", "fcvtps", "fcvtpu"};
                                    instruction = instructions[op];

                                    if (op == 0b00010 || op == 0b00011 || op == 0b00111)
                                        simd_first = 1;
                                }

                                snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, simd_first ? 16 : 32, simd_first), reg(rn, 0, simd_first ? 32 : 16, !simd_first));
                                break;
                            }
                        }
                    }
                }
                else if ((op3 & 0b000011111) == 0b000010000)
                {
                    // floating-point data-processing (1 source)
                    
                    bool M = masks(instruction, 0b1, 31);
                    bool S = masks(instruction, 0b1, 29);
                    uint8_t ptype = masks(instruction, 0b11, 22);
                    uint8_t opcode = masks(instruction, 0b111111, 15);
                    uint8_t rn = masks(instruction, 0b11111, 5);
                    uint8_t rd = mask(instruction, 0b11111);

                    if (M || S || (opcode >> 5))
                        return;

                    if (opcode & 0b010000)
                    {
                        // armv8.5

                        if (ptype == 0b11)
                            return;
                    }
                        
                    uint8_t bits;

                    switch (ptype)
                    {
                        case 0b00: bits = 32; break;
                        case 0b01: bits = 64; break;
                        case 0b11: bits = 16; break; // armv8.2
                        default: return;
                    }

                    uint8_t bits2 = bits;
                    const char *instruction;
                    
                    switch (opcode)
                    {
                        case 0b000000: instruction = "fmov"; break;
                        case 0b000001: instruction = "fabs"; break;
                        case 0b000010: instruction = "fneg"; break;
                        case 0b000011: instruction = "fsqrt"; break;
                        case 0b010000: instruction = "frint32z"; break; // armv8.5
                        case 0b010001: instruction = "frint32x"; break; // armv8.5
                        case 0b010010: instruction = "frint64z"; break; // armv8.5
                        case 0b010011: instruction = "frint64x"; break; // armv8.5
                        
                        case 0b000100:
                        {
                            instruction = "fcvt";
                            bits2 = 32;
                            break;
                        }

                        case 0b000101:
                        {
                            instruction = "fcvt";
                            bits2 = 64;
                            break;
                        }

                        case 0b000111:
                        {
                            // armv8.2
                            instruction = "fcvt";
                            bits2 = 16;
                            break;
                        }

                        default: return;
                    }

                    snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rd, 0, bits2, 1), reg(rn, 0, bits, 1));
                }
                else if ((op3 & 0b000001111) == 0b000001000)
                {
                    // floating-point compare

                    bool M = masks(instruction, 0b1, 31);
                    bool S = masks(instruction, 0b1, 29);
                    uint8_t ptype = masks(instruction, 0b11, 22);
                    uint8_t rm = masks(instruction, 0b11111, 16);
                    uint8_t op = masks(instruction, 0b11, 14);
                    uint8_t rn = masks(instruction, 0b11111, 5);
                    uint8_t opcode2 = mask(instruction, 0b11111);

                    bool zero = (opcode2 & 0b01000);

                    if (M || S || op || (zero && rm))
                        return;

                    uint8_t bits;

                    switch (ptype)
                    {
                        case 0b00: bits = 32; break;
                        case 0b01: bits = 64; break;
                        case 0b11: bits = 16; break; // armv8.2
                        default: return;
                    }

                    const char *instruction = (opcode2 & 0b10000) ? "fcmpe" : "fcmp";

                    snprintf(context->decode_string, 512, "%s %s, %s", instruction, reg(rn, 0, bits, 1), zero ? fimm(0, context) : reg(rm, 0, bits, 1));
                }
                else if ((op3 & 0b000000111) == 0b000000100)
                {
                    // floating-point immediate

                    bool M = masks(instruction, 0b1, 31);
                    bool S = masks(instruction, 0b1, 29);
                    uint8_t ptype = masks(instruction, 0b11, 22);
                    float imm8 = masks(instruction, 0b11111111, 13);
                    uint8_t imm5 = masks(instruction, 0b11111, 5);
                    uint8_t rd = mask(instruction, 0b11111);

                    if (M || S || imm5)
                        return;

                    uint8_t bits;

                    switch (ptype)
                    {
                        case 0b00: bits = 32; break;
                        case 0b01: bits = 64; break;
                        case 0b11: bits = 16; break; // armv8.2
                        default: return;
                    }

                    double f = build_float(imm8, bits);

                    snprintf(context->decode_string, 512, "fmov %s, %s", reg(rd, 0, bits, 1), fimm(f, context));
                }
                else if ((op3 & 0b000000011) == 0b000000001)
                {
                    // floating-point conditional compare
                    
                    bool M = masks(instruction, 0b1, 31);
                    bool S = masks(instruction, 0b1, 29);
                    uint8_t ptype = masks(instruction, 0b11, 22);
                    uint8_t rm = masks(instruction, 0b11111, 16);
                    uint8_t cond = masks(instruction, 0b1111, 12);
                    uint8_t rn = masks(instruction, 0b11111, 5);
                    bool op = masks(instruction, 0b1, 4);
                    uint8_t nzcv = mask(instruction, 0b1111);

                    if (M || S)
                        return;

                    uint8_t bits;

                    switch (ptype)
                    {
                        case 0b00: bits = 32; break;
                        case 0b01: bits = 64; break;
                        case 0b11: bits = 16; break; // armv8.2
                        default: return;
                    }

                    snprintf(context->decode_string, 512, "%s %s, %s, %s, %s", op ? "fccmpe" : "fccmp", reg(rn, 0, bits, 1), reg(rm, 0, bits, 1), imm(nzcv, context, 0), decode_condition(cond));
                }
                else if ((op3 & 0b000000011) == 0b000000010)
                {
                    // floating-point data processing (2 source)

                    bool M = masks(instruction, 0b1, 31);
                    bool S = masks(instruction, 0b1, 29);
                    uint8_t ptype = masks(instruction, 0b11, 22);
                    uint8_t rm = masks(instruction, 0b11111, 16);
                    uint8_t opcode = masks(instruction, 0b1111, 12);
                    uint8_t rn = masks(instruction, 0b11111, 5);
                    uint8_t rd = mask(instruction, 0b11111);

                    if (M || S || opcode > 0b1000)
                        return;

                    uint8_t bits;

                    switch (ptype)
                    {
                        case 0b00: bits = 32; break;
                        case 0b01: bits = 64; break;
                        case 0b11: bits = 16; break; // armv8.2
                        default: return;
                    }

                    static const char *instructions[] = {"fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm", "fnmul"};
                    const char *instruction = instructions[opcode];

                    snprintf(context->decode_string, 512, "%s %s, %s, %s", instruction, reg(rd, 0, bits, 1), reg(rn, 0, bits, 1), reg(rm, 0, bits, 1));
                }
                else if ((op3 & 0b000000011) == 0b000000011)
                {
                    // floating point conditional select
                    
                    bool M = masks(instruction, 0b1, 31);
                    bool S = masks(instruction, 0b1, 29);
                    uint8_t ptype = masks(instruction, 0b11, 22);
                    uint8_t rm = masks(instruction, 0b11111, 16);
                    uint8_t cond = masks(instruction, 0b1111, 12);
                    uint8_t rn = masks(instruction, 0b11111, 5);
                    uint8_t rd = mask(instruction, 0b11111);

                    if (M || S)
                        return;

                    uint8_t bits;

                    switch (ptype)
                    {
                        case 0b00: bits = 32; break;
                        case 0b01: bits = 64; break;
                        case 0b11: bits = 16; break; // armv8.2
                        default: return;
                    }

                    snprintf(context->decode_string, 512, "fcsel %s, %s, %s, %s", reg(rd, 0, bits, 1), reg(rn, 0, bits, 1), reg(rm, 0, bits, 1), decode_condition(cond));
                }
            }
            else
            {
                // conversion between floating-point and fixed-point

                bool sf = masks(instruction, 0b1, 31);
                bool S = masks(instruction, 0b1, 29);
                uint8_t ptype = masks(instruction, 0b11, 22);
                uint8_t rmode = masks(instruction, 0b11, 19);
                uint8_t opcode = masks(instruction, 0b111, 16);
                uint8_t scale = masks(instruction, 0b111111, 10);
                uint8_t rn = masks(instruction, 0b11111, 5);
                uint8_t rd = mask(instruction, 0b11111);

                if (S || (!sf && !(scale >> 5)))
                    return;

                uint8_t bits;

                switch (ptype)
                {
                    case 0b00: bits = 32; break;
                    case 0b01: bits = 64; break;
                    case 0b11: bits = 16; break; // armv8.2
                    default: return;
                }

                switch (rmode)
                {
                    case 0b00:
                    {
                        char *instruction;

                        switch (opcode)
                        {
                            case 0b010: instruction = "scvtf"; break;
                            case 0b011: instruction = "ucvtf"; break;
                            default: return;
                        }

                        snprintf(context->decode_string, 512, "%s %s, %s, %s", instruction, reg(rd, 0, bits, 1), reg(rn, 0, sf, 0), imm(64 - scale, context, 0));
                        break;
                    }

                    case 0b11:
                    {
                        char *instruction;

                        switch (opcode)
                        {
                            case 0b000: instruction = "fcvtzs"; break;
                            case 0b001: instruction = "fvctzu"; break;
                            default: return;
                        }

                        snprintf(context->decode_string, 512, "%s %s, %s, %s", instruction, reg(rd, 0, sf, 0), reg(rn, 0, bits, 1), imm(64 - scale, context, 0));
                        break;
                    }
                }
            }
        }
    }
}

void do_nothing() {}

bool disassemble_master(decode_context_t *context)
{
    *context->decode_string = '\0';

	uint8_t group = masks(context->instruction, 0b1111, 25);
	static uint8_t group_mask[] = { 0b1111, 0b1111, 0b1111, 0b1111, 0b1110, 0b1110, 0b0101, 0b0111, 0b0111 };
	static uint8_t group_id[] = { 0b0000, 0b0001, 0b0010, 0b0011, 0b1000, 0b1010, 0b0100, 0b0101, 0b0111 };

    int g = index_match(group, group_mask, group_id, 9);

    context->group = g;

    if (g == -1)
        return 0;

    void (*disassemble_functions[])(decode_context_t *a) = {disassemble_reserved, do_nothing, disassemble_sve, do_nothing, disassemble_data_immediate, disassemble_system, disassemble_loads_stores, disassemble_data_register, disassemble_data_float};
    disassemble_functions[g](context);

    if (!*context->decode_string)
        return 0;

    return 1;
}