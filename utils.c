#define _CRT_SECURE_NO_WARNINGS

#include "defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include "utils.h"

void disassemble(uint32_t instr, char *asm_output)
{
	*asm_output = '\0';

	// little endian
	instr = swap_uint32_t(instr);

	int opcode = masks(instr, 0b1111, 25);
	int opcode_masks[]  = { 0b1111, 0b1111, 0b1111, 0b1111, 0b1110, 0b1110, 0b0101, 0b0111, 0b0111 };
	int opcode_group[] = { 0b0000, 0b0001, 0b0010, 0b0011, 0b1000, 0b1010, 0b0100, 0b0101, 0b0111 };

	bool found = false;

	for (int i = 0; i < 9; i++)
	{
		if (found)
			goto found_instruction;

		if (mask(opcode, opcode_masks[i]) == opcode_group[i])
		{
			found = true;

			switch (i)
			{

				case 4: // data processing -- immediate
				{
					int op0 = masks(instr, 0b111, 23);
					int op0_masks[] = { 0b110, 0b111, 0b111, 0b111, 0b111, 0b111, 0b111 };
					int op0_instr[] = { 0b000, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111 };

					bool sf = masks(instr, 0b1, 31);
					bool op = masks(instr, 0b1, 30);
					int opc = masks(instr, 0b11, 29);
					bool s = masks(instr, 0b1, 29);
					bool sh = masks(instr, 0b1, 22);
					int rn = masks(instr, 0b11111, 5);
					int rd = mask(instr, 0b11111);
					
					int immr = masks(instr, 0b111111, 16);
					int imms = masks(instr, 0b111111, 10);

					for (int ii = 0; ii < 6; ii++)
					{
						if (mask(op0, op0_masks[ii]) == op0_instr[ii])
						{
							switch (ii)
							{
								case 0:
								{
									bool op = masks(instr, 0b1, 31);
									int immhi = masks(instr, 0b111111111111111111, 5);
									int immlo = masks(instr, 0b11, 29);

									sprintf(asm_output, "adr%s x%d, #0x%x", op ? "p" : "", rd, (immhi << 2) + immlo);
									break;
								}

								case 1:
								{
									int imm12 = masks(instr, 0b111111111111, 10);

									char inst[5];
									if (op)
										strcpy(inst, "sub");
									else
										strcpy(inst, "add");
									if (s)
										strcat(inst, "s");

									char shift[14];
									if (sh)
										sprintf(shift, ", lsl #0x%x", sh * 12);
									else
										strcpy(shift, "");

									sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, #0x%5$x%6$s", inst, sf ? 'x' : 'w', rd, rn, imm12, shift);
									break;
								}

								case 2:
								{
									if ((s && sf) || (s || !sf))
										goto unknown_instruction;

									int uimm6 = masks(instr, 0b111111, 16);
									int uimm4 = masks(instr, 0b1111, 10);

									sprintf(asm_output, "%s x%d, x%d, #0x%x, #0x%x", op ? "subg" : "addg", rd, rn, uimm6, uimm4);
									break;
								}

								case 3:
								{
									if (!sf && sh)
										goto unknown_instruction;

									char inst[5];
									switch (opc)
									{
										case 0b00:
										{
											strcpy(inst, "and");
											break;
										}

										case 0b01:
										{
											strcpy(inst, "orr");
											break;
										}

										case 0b10:
										{
											strcpy(inst, "eor");
											break;
										}

										case 0b11:
										{
											strcpy(inst, "ands");
											break;
										}
									}

									// thank you qemu, this operation is horrid. /*
									// https://github.com/qemu/qemu/blob/master/target/arm/translate-a64.c#L3696

									int len = 31 - __builtin_clz((sh << 6) | (~imms & 0x3f));

									if (len < 1)
										goto unknown_instruction;

									uint32_t e = 1 << len;
									uint32_t levels = e - 1;
									uint32_t s = imms & levels;
									uint32_t r = immr & levels;

									if (s == levels)
										goto unknown_instruction;

									uint64_t mask = (~0ULL >> (63 - s));

									if (r)
									{
										mask = (mask >> r) | (mask << (e - r));
										mask &= (~0ULL >> (64 - e));
									}

									while (e < 64)
									{
										mask |= mask << e;
										e *= 2;
									}

									// */

									sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, #0x%5$llx", inst, sf ? 'x' : 'w', rd, rn, mask);
									break;
								}

								case 4:
								{
									if (opc == 1 || (!sf && sh))
										goto unknown_instruction;

									int hw = masks(instr, 0b11, 21);
									int imm16 = masks(instr, 0b1111111111111111, 5);
									char shift[14];

									if (hw)
										sprintf(shift, ", lsl #0x%x", hw * 16);
									else
										strcpy(shift, "");

									sprintf(asm_output, "mov%c %c%d, #0x%x%s", opc == 0 ? 'n' : (opc == 2 ? 'z' : 'k'), sf ? 'x' : 'w', rd, imm16, shift);
									break;
								}

								case 5:
								{
									if (opc == 3 || (!sf && sh) || (sf && !sh))
										goto unknown_instruction;

									bool b = (!sf && !sh);

									sprintf(asm_output, "%sbfm %c%d, %c%d, #0x%x, #0x%x", opc == 0 ? "s" : (opc == 1 ? "" : "u"), b ? 'w' : 'x', rd, b ? 'w' : 'x', rn, immr, imms);
									break;
								}

								case 6:
								{
									if (sf != sh || opc != 0 || (sf && masks(imms, 0b1, 5)))
										goto unknown_instruction;

									bool b = (sf && sh && !masks(imms, 0b1, 5));
									int rm = masks(instr, 0b11111, 16);

									sprintf(asm_output, "extr %c%d, %c%d, %c%d, #0x%x", b ? 'w' : 'x', rd, b ? 'w' : 'x', rn, b ? 'w' : 'x', rm, imms);
									break;
								}

								default:
									goto unknown_instruction;
							}
						}
					}
					
					break;
				}

				case 7: // data processing -- register
				{
					bool op0 = masks(instr, 0b1, 30);
					bool op1 = masks(instr, 0b1, 28);
					int op2 = masks(instr, 0b111, 21);
					int op3 = masks(instr, 0b111111, 10);

					int rd = mask(instr, 0b11111);
					int rn = masks(instr, 0b11111, 5);
					int rm = masks(instr, 0b11111, 16);

					bool sf = masks(instr, 0b1, 31);

					if (op1 && op2 == 0b0110)
					{
						bool s = masks(instr, 0b1, 29);

						if (op0) // 1 source
						{
							if ((masks(rm, 0b1111, 1) != masks(rm, 0b0000, 1)) || s || (rm == 1 && !sf))
								goto unknown_instruction;

							if (rm == 0)
							{
								// thank god for the fact that these opcodes don't use masks
								int op3_instr[] = { 0b000000, 0b000001, 0b000010, 0b000011, 0b000100, 0b000101, 0b000110, 0b000111, 0b001000, 0b001001, 0b0010011, 0b001100, 0b001101, 0b001110, 0b010000, 0b010001 };
								for (int ii = 0; ii < 15; ii++)
								{
									if (op3 == op3_instr[ii])
									{
										switch (op3)
										{
											case 0b000000:
											{
												sprintf(asm_output, "rbit %1$c%2$d, %1$c%3$d", sf ? 'x' : 'w', rd, rn);
												break;
											}

											case 0b000001:
											{
												sprintf(asm_output, "rev16 %1$c%2$d, %1$c%3$d", sf ? 'x' : 'w', rd, rn);
												break;
											}

											case 0b000010:
											{
												sprintf(asm_output, "rev%4$s %1$c%2$d, %1$c%3$d", sf ? 'x' : 'w', rd, rn, sf ? "32" : "");
												break;
											}

											case 0b000011:
											{
												if (!sf)
													goto unknown_instruction;

												sprintf(asm_output, "rev %1$c%2$d, %1$c%3$d", sf ? 'x' : 'w', rd, rn);
												break;
											}

											case 0b000100:
											{
												sprintf(asm_output, "clz %1$c%2$d, %1$c%3$d", sf ? 'x' : 'w', rd, rn);
												break;
											}

											case 0b000101:
											{
												sprintf(asm_output, "cls %1$c%2$d, %1$c%3$d", sf ? 'x' : 'w', rd, rn);
												break;
											}
										}
									}
								}
							}
							else if (rm == 1 && s)
							{
								// yay no masks here either
								int op3_instr[] = { 0b000000, 0b000001, 0b000010, 0b000011, 0b000100, 0b000101, 0b000110, 0b000111, 0b001000, 0b001001, 0b001010, 0b001011, 0b001100, 0b001101, 0b001110, 0b001111, 0b010000, 0b010001 };
								for (int ii = 0; ii < 17; ii++)
								{
									if (op3 == op3_instr[ii])
									{
										if (op3 > 0b000111 && rm != 0b11111)
											goto unknown_instruction;
										
										switch (op3)
										{
											case 0b000000:
											{
												// yeahhhh ill do PAC instructions later...

												break;
											}
										}
									}
								}
							}
						}
						else // 2 source
						{
							if (s)
							{
								if (sf && s && op3 == 0b0)
									sprintf(asm_output, "subps x%d, x%d, x%d", rn, rd, rm);
								else
									goto unknown_instruction;

								break;
							}
							
							int op3_masks[] = { 0b111111, 0b111111, 0b111111, 0b111111, 0b111111, 0b111111, 0b111111, 0b111111, 0b111111, 0b111111, 0b111000 };
							int op3_instr[] = { 0b000000, 0b000010, 0b000011, 0b000100, 0b000101, 0b001000, 0b001001, 0b001010, 0b001011, 0b001100, 0b010000 };

							for (int ii = 0; ii < 10; ii++)
							{
								if (mask(op3, op3_masks[ii]) == op3_instr[ii])
								{
									switch (op3)
									{
										case 0b000000:
										{
											sprintf(asm_output, "subs x%d, x%d, x%d", rn, rd, rm);
											break;
										}

										case 0b000010:
										{
											sprintf(asm_output, "udiv %1$c%2$d, %1$c%3$d, %1$c%4$d", sf ? 'x' : 'w', rd, rn, rm);
											break;
										}

										case 0b000011:
										{
											sprintf(asm_output, "udiv %1$c%2$d, %1$c%3$d, %1$c%4$d", sf ? 'x' : 'w', rd, rn, rm);
											break;
										}

										case 0b000100:
										{
											if (!sf)
												goto unknown_instruction;

											char optional[4];
											if (rm == 0)
												sprintf(optional, "xzr");
											else
												sprintf(optional, "x%d", rm);
												
											sprintf(asm_output, "irg x%d, x%d%s", rd, rn, optional);
											break;
										}

										case 0b000101:
										{
											if (!sf)
												goto unknown_instruction;

											sprintf(asm_output, "gmi x%d, x%d, x%d", rd, rn, rm);
											break;
										}

										case 0b001000:
										{
											sprintf(asm_output, "lslv %1$c%2$d, %1$c%3$d, %1$c%4$d", sf ? 'x' : 'w', rd, rn, rm);
											break;
										}

										case 0b001001:
										{
											sprintf(asm_output, "lsrv %1$c%2$d, %1$c%3$d, %1$c%4$d", sf ? 'x' : 'w', rd, rn, rm);
											break;
										}

										case 0b001010:
										{
											sprintf(asm_output, "asrv %1$c%2$d, %1$c%3$d, %1$c%4$d", sf ? 'x' : 'w', rd, rn, rm);
											break;
										}

										case 0b001011:
										{
											sprintf(asm_output, "rorv %1$c%2$d, %1$c%3$d, %1$c%4$d", sf ? 'x' : 'w', rd, rn, rm);
											break;
										}

										case 0b001100:
										{
											if (!sf)
												goto unknown_instruction;

											sprintf(asm_output, "pacga, x%d, x%d, x%d", rd, rn, rm);
											break;
										}

										case 0b010000:
										{
											bool c = masks(instr, 0b1, 12);
											int sz = masks(instr, 0b11, 10);

											if ((sf && sz != 0b11) || (!sf && sz == 0b11))
												goto unknown_instruction;

											char add;
											if (sz == 0)
												add = 'b';
											else if (sz == 1)
												add = 'h';
											else if (sz == 2)
												add = 'w';
											else
												add = 'x';

											sprintf(asm_output, "crc32%s%c w%d, w%d, w%d", c ? "c" : "", add, rd, rn, rm);
											break;
										}
									}
								}
							}
						}
					}

					if (op1)
					{
						
					}
					else
					{
						int op2_masks[] = { 0b1000, 0b1001, 0b1001 };
						int op2_instr[] = { 0b0000, 0b1000, 0b1001 };

						for (int ii = 0; ii < 2; ii++)
						{
							if (mask(op2, op2_masks[ii]) == op2_instr[ii])
							{
								switch (op2)
								{
									case 0b0000:
									{
										int opc = masks(instr, 0b11, 29);
										int shift = masks(instr, 0b11, 22);
										// bool n = masks(instr, 0b1, 21);
										// int imm6 = masks(instr, 0b111111, 10);

										char shift_operation[4] = { 0 };
										switch (shift)
										{
											case 0b00:
											{
												strcpy(shift_operation, "lsl");
												break;
											}

											case 0b01:
											{
												strcpy(shift_operation, "lsr");
												break;
											}

											case 0b10:
											{
												strcpy(shift_operation, "asr");
												break;
											}

											case 0b11:
											{
												strcpy(shift_operation, "ror");
												break;
											}
										}

										switch (opc)
										{
											case 0b00:
											{

												break;
											}
										}

										break;
									}
								}
							}
						}
					}
				
					break;
				}

				case 0: // reserved
				case 1: // unallocated space
				case 2: // sve (scalable vector extension) -- i have no clue what this does. doesn't seem to contain any real instructions.
				case 3: // unallocated space
				case 5: // branches, exception generating, and system instructions
				case 6: // loads and stores
				case 8: // data processing -- scalar floating-point and advanced simd
				default:
				{
					found = false;
					break;
				}
			}
		}
	}

	found_instruction:

	if (strlen(asm_output) == 0)
		goto unknown_instruction;
	
	if (420 == 69)
	{
		unknown_instruction:
		sprintf(asm_output, "[unknown instruction]");
	}

	// change later. x31/w31 is not always the stack pointer, but we can assume it is for now.
	str_replace(asm_output, "x31", "sp");
	str_replace(asm_output, "w31", "sp");
}

void *read_bytes(FILE *file, int offset, int size)
{
	void *buffer = calloc(1, size);
	fseek(file, offset, SEEK_SET);
	fread(buffer, size, 1, file);
	return buffer;
}

uint32_t read_uint32_t(FILE *file, int offset)
{
	uint32_t r;
	fseek(file, offset, SEEK_SET);
	fread(&r, sizeof(uint32_t), 1, file);
	return r;
}

void read_string(FILE *file, int offset, char *buffer, int buffer_size)
{
	sprintf(buffer, "");
	int c = 0;
	
	fseek(file, offset, SEEK_SET);
	while ((c = fgetc(file)) != '\0' && c != EOF && c < buffer_size)
	{
		strcat(buffer, (char *)&c);
		c++;
	}
}

void str_replace(char *target, const char *needle, const char *replacement)
{
    char buffer[1024] = { 0 };
    char *insert_point = &buffer[0];
    const char *tmp = target;
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(replacement);

    while (true)
	{
        const char *p = strstr(tmp, needle);
        if (!p)
		{
            strcpy(insert_point, tmp);
            break;
        }

        memcpy(insert_point, tmp, p - tmp);
        insert_point += p - tmp;

        memcpy(insert_point, replacement, repl_len);
        insert_point += repl_len;
		
        tmp = p + needle_len;
    }
	
    strcpy(target, buffer);
}

int swap_int32(int value)
{
    return (((value & 0x000000FF) << 24) | ((value & 0x0000FF00) <<  8) | ((value & 0x00FF0000) >>  8) | ((value & 0xFF000000) >> 24));
}

uint32_t swap_uint32_t(uint32_t value)
{
    return (((value & 0x000000FF) << 24) | ((value & 0x0000FF00) <<  8) | ((value & 0x00FF0000) >>  8) | ((value & 0xFF000000) >> 24));
}

int64_t swap_int64_t(int64_t value)
{
    return ((((uint64_t)(value) & 0xff00000000000000ULL) >> 56) | 
			(((uint64_t)(value) & 0x00ff000000000000ULL) >> 40) | 
			(((uint64_t)(value) & 0x0000ff0000000000ULL) >> 24) | 
			(((uint64_t)(value) & 0x000000ff00000000ULL) >>  8) | 
			(((uint64_t)(value) & 0x00000000ff000000ULL) <<  8) | 
			(((uint64_t)(value) & 0x0000000000ff0000ULL) << 24) | 
			(((uint64_t)(value) & 0x000000000000ff00ULL) << 40) | 
			(((uint64_t)(value) & 0x00000000000000ffULL) << 56));
}

static struct cpu_pair cpu_types[] = 
{
	{ { CPU_TYPE_I386, CPU_SUBTYPE_MULTIPLE }, "i386" },
	{ { CPU_TYPE_X86, CPU_SUBTYPE_MULTIPLE }, "x86" },
	{ { CPU_TYPE_X86_64, CPU_SUBTYPE_MULTIPLE }, "x86_64" },
	{ { CPU_TYPE_ARM64_32, CPU_SUBTYPE_MULTIPLE }, "arm64_32" },
	{ { CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6 }, "armv6" },
	{ { CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7 }, "armv7" },
	{ { CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S }, "armv7s" },
	{ { CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL }, "arm64" },
	{ { CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E }, "arm64e" }
};

char *name_for_cpu(struct cpu *cpu)
{
	for (int i = 0; i < 9; i++)
	{
		if (cpu->cpu_type == cpu_types[i].cpu.cpu_type && (cpu_types[i].cpu.cpu_subtype == CPU_SUBTYPE_MULTIPLE || cpu->cpu_subtype == cpu_types[i].cpu.cpu_subtype))
			return cpu_types[i].cpu_name;
	}

	static char cpu_info[128];
	sprintf(cpu_info, "unknown: cpu_type (0x%x) cpu_subtype (0x%x)", cpu->cpu_type, cpu->cpu_subtype);

	return cpu_info;
}

struct cpu *cpu_for_name(char *cpu_name)
{
	for (int i = 0; i < 9; i++)
	{
		if (strcmp(cpu_name, cpu_types[i].cpu_name) == 0)
			return &(cpu_types[i].cpu);
	}

	return NULL;
}