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
							switch (op0_instr[ii])
							{
								case 0b000:
								{
									bool op = masks(instr, 0b1, 31);
									int immhi = masks(instr, 0b111111111111111111, 5);
									int immlo = masks(instr, 0b11, 29);

									sprintf(asm_output, "adr%s x%d, #0x%x", op ? "p" : "", rd, (immhi << 2) + immlo);
									break;
								}

								case 0b010:
								{
									int imm12 = masks(instr, 0b111111111111, 10);

									char inst[5] = { 0 };
									if (op)
										strcpy(inst, "sub");
									else
										strcpy(inst, "add");
									if (s)
										strcat(inst, "s");

									char shift[11] = { 0 };
									if (sh)
										sprintf(shift, ", lsl #0x%x", sh * 12);
									else
										strcpy(shift, "");

									sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, #0x%5$x%6$s", inst, sf ? 'x' : 'w', rd, rn, imm12, shift);
									break;
								}

								case 0b011:
								{
									if ((s && sf) || (s || !sf))
										goto unknown_instruction;

									int uimm6 = masks(instr, 0b111111, 16);
									int uimm4 = masks(instr, 0b1111, 10);

									sprintf(asm_output, "%s x%d, x%d, #0x%x, #0x%x", op ? "subg" : "addg", rd, rn, uimm6, uimm4);
									break;
								}

								case 0b100:
								{
									if (!sf && sh)
										goto unknown_instruction;

									char inst[5] = { 0 };
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

									// thank you qemu, this operation is horrid.
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

									sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, #0x%5$llx", inst, sf ? 'x' : 'w', rd, rn, mask);
									break;
								}

								case 0b101:
								{
									if (opc == 1 || (!sf && sh))
										goto unknown_instruction;

									int hw = masks(instr, 0b11, 21);
									int imm16 = masks(instr, 0b1111111111111111, 5);
									char shift[12] = { 0 };

									if (hw)
										sprintf(shift, ", lsl #0x%x", hw * 16);
									else
										strcpy(shift, "");

									sprintf(asm_output, "mov%c %c%d, #0x%x%s", opc == 0 ? 'n' : (opc == 2 ? 'z' : 'k'), sf ? 'x' : 'w', rd, imm16, shift);
									break;
								}

								case 0b110:
								{
									if (opc == 3 || (!sf && sh) || (sf && !sh))
										goto unknown_instruction;

									bool b = (!sf && !sh);

									sprintf(asm_output, "%sbfm %c%d, %c%d, #0x%x, #0x%x", opc == 0 ? "s" : (opc == 1 ? "" : "u"), b ? 'w' : 'x', rd, b ? 'w' : 'x', rn, immr, imms);
									break;
								}

								case 0b111:
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
					int op2 = masks(instr, 0b1111, 21);
					int op3 = masks(instr, 0b111111, 10);

					int rd = mask(instr, 0b11111);
					int rn = masks(instr, 0b11111, 5);
					int rm = masks(instr, 0b11111, 16);

					bool sf = masks(instr, 0b1, 31);

					if (op1 && op2 == 0b0110)
					{
						bool s = masks(instr, 0b1, 29);

						if (op0)
						{
							if ((masks(rm, 0b1111, 1) != masks(rm, 0b0000, 1)) || s || (rm == 1 && !sf))
								goto unknown_instruction;

							if (rm == 0)
							{
								// thank god for the fact that these opcodes don't use masks
								int op3_group[] = { 0b000000, 0b000001, 0b000010, 0b000011, 0b000100, 0b000101, 0b000110, 0b000111, 0b001000, 0b001001, 0b0010011, 0b001100, 0b001101, 0b001110, 0b010000, 0b010001 };
								for (int ii = 0; ii < 15; ii++)
								{
									if (op3 == op3_group[ii])
									{
										switch (op3_group[ii])
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

											default:
												goto unknown_instruction;
										}
									}
								}
							}
							else if (rm == 1 && s)
							{
								// yay no masks here either
								int op3_group[] = { 0b000000, 0b000001, 0b000010, 0b000011, 0b000100, 0b000101, 0b000110, 0b000111, 0b001000, 0b001001, 0b001010, 0b001011, 0b001100, 0b001101, 0b001110, 0b001111, 0b010000, 0b010001 };
								for (int ii = 0; ii < 17; ii++)
								{
									if (op3 == op3_group[ii])
									{
										if (op3 > 0b000111 && rm != 0b11111)
											goto unknown_instruction;
										
										switch (op3_group[ii])
										{
											case 0b000000:
											{
												// yeahhhh ill do PAC instructions later...

												break;
											}

											default:
												goto unknown_instruction;
										}
									}
								}
							}
						}
						else
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
							int op3_group[] = { 0b000000, 0b000010, 0b000011, 0b000100, 0b000101, 0b001000, 0b001001, 0b001010, 0b001011, 0b001100, 0b010000 };

							for (int ii = 0; ii < 10; ii++)
							{
								if (mask(op3, op3_masks[ii]) == op3_group[ii])
								{
									switch (op3_group[ii])
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

											char optional[4] = { 0 };
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

										default:
											goto unknown_instruction;
									}
								}
							}
						}
					}

					if (op1)
					{
						int op2_masks[] = { 0b1111, 0b1111, 0b1111, 0b1000 };
						int op2_group[] = { 0b0000, 0b0010, 0b0100, 0b1000 };
						
						int mask = mask(instr, 0b111);
						int opc = masks(instr, 0b11, 29);
						int cond = masks(instr, 0b1111, 12);
						bool s = masks(instr, 0b1, 29);
						bool o3 = masks(instr, 0b1, 4);

						for (int ii = 0; ii < 3; ii++)
						{
							if (mask(op2, op2_masks[ii]) == op2_group[ii])
							{
								switch (op2_group[ii])
								{
									case 0b0000:
									{
										int op3_masks[] = { 0b111111, 0b011111, 0b001111, 0b000010, 0b000010 };
										int op3_group[] = { 0b000000, 0b000001, 0b000010, 0b000000, 0b000010 };

										int imm6 = masks(instr, 0b111111, 15);

										for (int iii = 0; iii < 4; iii++)
										{
											if (mask(op3, op3_masks[iii]) == op3_group[iii])
											{
												switch (op3_group[iii])
												{
													case 0b000000:
													{
														char inst[5] = { 0 };
														switch (opc)
														{
															case 0b00:
															{
																strcpy(inst, "adc");
																break;
															}

															case 0b01:
															{
																strcpy(inst, "adcs");
																break;
															}

															case 0b10:
															{
																strcpy(inst, "sbc");
																break;
															}

															case 0b11:
															{
																strcpy(inst, "sbcs");
																break;
															}
														}

														sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, %2$c%5$d", inst, sf ? 'x' : 'w', rd, rn, rm);
														break;
													}

													case 0b000001:
													{
														if (opc != 0b01 || !sf || !o3)
															goto unknown_instruction;

														sprintf(asm_output, "rmif x%d, #0x%x, #0x%x", rn, imm6, mask);
														break;
													}

													case 0b000010:
													{
														if (mask != 0b1101 || o3 || imm6 != 0b000000 || sf || opc != 0b01)
															goto unknown_instruction;

														bool sz = masks(instr, 0b1, 14);

														sprintf(asm_output, "setf%d w%d", sz ? 16 : 8, rn);
														break;
													}
												}
											}
										}

										break;
									}

									case 0b0010:
									{
										bool o2 = masks(instr, 0b1, 10);

										if (o3 || o2 || !s)
											goto unknown_instruction;

										char inst[5] = { 0 };
										if (opc == 0b01)
											strcpy(inst, "ccmn");
										else
											strcpy(inst, "ccmn");

										char rm_imm5[6] = { 0 };
										if (masks(instr, 0b1, 11))
											sprintf(rm_imm5, "#0x%x", rm);
										else
											sprintf(rm_imm5, "%c%d", sf ? 'x' : 'w', rm);

										sprintf(asm_output, "%s %c%d, %s, #0x%x, %s", inst, sf ? 'x' : 'w', rn, rm_imm5, mask, cond_string(cond));
										break;
									}

									case 0b0100:
									{
										int op = masks(instr, 0b11, 10);

										if (s || op > 0b1)
											goto unknown_instruction;

										char inst[6] = { 0 };
										switch (opc + op)
										{
											case 0b00:
											{
												strcpy(inst, "csel");
												break;
											}

											case 0b01:
											{
												strcpy(inst, "csinc");
												break;
											}

											case 0b10:
											{
												strcpy(inst, "csinv");
												break;
											}

											case 0b11:
											{
												strcpy(inst, "cseng");
												break;
											}
										}

										sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, %2$c%5$d, %6$s", inst, sf ? 'x' : 'w', rd, rn, rm, cond_string(cond));
										break;
									}

									case 0b1000:
									{
										
										break;
									}

									default:
										goto unknown_instruction;
								}
							}
						}
					}
					else
					{
						int op2_masks[] = { 0b1000, 0b1001, 0b1001 };
						int op2_group[] = { 0b0000, 0b1000, 0b1001 };
						
						int shift = masks(instr, 0b11, 22);
						int imm6 = masks(instr, 0b111111, 10);

						for (int ii = 0; ii < 3; ii++)
						{
							if (mask(op2, op2_masks[ii]) == op2_group[ii])
							{
								switch (op2_group[ii])
								{
									case 0b0000:
									{
										if (!sf && masks(imm6, 0b1, 5))
											goto unknown_instruction;

										bool n = masks(instr, 0b1, 21);
										int opc = masks(instr, 0b110, 28) + n;

										char shift_string[12] = { 0 };

										if (imm6)
											sprintf(shift_string, ", %s #0x%x", decode_shift(shift), imm6);

										char inst[5] = { 0 };
										switch (opc)
										{
											case 0b000:
											{
												strcpy(inst, "and");
												break;
											}

											case 0b001:
											{
												strcpy(inst, "bic");
												break;
											}

											case 0b010:
											{
												strcpy(inst, "orr");
												break;
											}

											case 0b011:
											{
												strcpy(inst, "orn");
												break;
											}

											case 0b100:
											{
												strcpy(inst, "eor");
												break;
											}

											case 0b101:
											{
												strcpy(inst, "eon");
												break;
											}

											case 0b110:
											{
												strcpy(inst, "ands");
												break;
											}

											case 0b111:
											{
												strcpy(inst, "bics");
												break;
											}
										}

										sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, %2$c%5$d%6$s", inst, sf ? 'x' : 'w', rd, rn, rm, shift_string);
										break;
									}

									case 0b1000:
									{
										if ((!sf && masks(imm6, 0b1, 5)) || shift == 0b11)
											goto unknown_instruction;

										int opc = masks(instr, 0b11, 29);

										char shift_string[12] = { 0 };
										if (imm6)
											sprintf(shift_string, ", %s #0x%x", decode_shift(shift), imm6);

										char inst[5] = { 0 };
										switch (opc)
										{
											case 0b00:
											{
												strcpy(inst, "add");
												break;
											}

											case 0b01:
											{
												strcpy(inst, "adds");
												break;
											}

											case 0b10:
											{
												strcpy(inst, "sub");
												break;
											}

											case 0b11:
											{
												strcpy(inst, "subs");
												break;
											}
										}
										
										sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, %2$c%5$d%6$s", inst, sf ? 'x' : 'w', rd, rn, rm, shift_string);
										break;
									}

									case 0b1001:
									{
										int option = masks(instr, 0b111, 13);
										int imm3 = masks(instr, 0b111, 10);
										int opc = masks(instr, 0b11, 29);

										if (shift != 0b00)
											goto unknown_instruction;

										char inst[5] = { 0 };
										switch (opc)
										{
											case 0b00:
											{
												strcpy(inst, "add");
												break;
											}

											case 0b01:
											{
												strcpy(inst, "adds");
												break;
											}

											case 0b10:
											{
												strcpy(inst, "sub");
												break;
											}

											case 0b11:
											{
												strcpy(inst, "subs");
												break;
											}
										}

										char extend[12] = { 0 };
										char ex_op[5] = { 0 };
										switch (option)
										{
											case 0b000:
											{
												strcpy(ex_op, "uxtb");
												break;
											}

											case 0b001:
											{
												strcpy(ex_op, "uxth");
												break;
											}

											case 0b010:
											{
												if (sf)
												{
													strcpy(ex_op, "uxtw");
													break;
												}

												if (rd == 0b11111 || rn == 0b11111)
												{
													strcpy(ex_op, "lsl");
													break;
												}

												strcpy(ex_op, "uxtw");
												break;
											}

											case 0b011:
											{
												if (!sf)
												{
													strcpy(ex_op, "uxtx");
													break;
												}

												if (rd == 0b11111 || rn == 0b11111)
												{
													strcpy(ex_op, "lsl");
													break;
												}

												strcpy(ex_op, "uxtx");
												break;
											}

											case 0b100:
											{
												strcpy(ex_op, "sxtb");
												break;
											}

											case 0b101:
											{
												strcpy(ex_op, "sxth");
												break;
											}

											case 0b110:
											{
												strcpy(ex_op, "sxtw");
												break;
											}

											case 0b111:
											{
												strcpy(ex_op, "sxtx");
												break;
											}
										}
										
										if (!imm3 && strcmp(ex_op, "lsl") == 0)
											strcpy(extend, "");
										else if (!imm3)
											sprintf(extend, ", %s", ex_op);
										else
											sprintf(extend, ", %s #0x%x", ex_op, imm3);

										char wxm[4] = { 0 };
										char r;
										if (mask(option, 0b011) == 0b011)
											r = 'x';
										else
											r = 'w';

										sprintf(wxm, "%c%d", r, rm);

										sprintf(asm_output, "%1$s %2$c%3$d, %2$c%4$d, %5$s%6$s", inst, sf ? 'x' : 'w', rd, rn, wxm, extend);
										break;
									}

									default:
										goto unknown_instruction;
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

uint8_t read_byte(FILE *file, int offset)
{
	uint8_t r;
	fseek(file, offset, SEEK_SET);
	fread(&r, sizeof(uint8_t), 1, file);
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

char *cond_string(int cond)
{
	static char cond_string[3] = { 0 };
	switch (cond)
	{
		case 0b0000:
		{
			strcpy(cond_string, "eq");
			break;
		}

		case 0b0001:
		{
			strcpy(cond_string, "ne");
			break;
		}

		case 0b0010:
		{
			strcpy(cond_string, "hs");
			break;
		}

		case 0b0011:
		{
			strcpy(cond_string, "mi");
			break;
		}

		case 0b0100:
		{
			strcpy(cond_string, "mi");
			break;
		}

		case 0b0101:
		{
			strcpy(cond_string, "pl");
			break;
		}

		case 0b0110:
		{
			strcpy(cond_string, "vs");
			break;
		}

		case 0b0111:
		{
			strcpy(cond_string, "vc");
			break;
		}

		case 0b1000:
		{
			strcpy(cond_string, "hi");
			break;
		}

		case 0b1001:
		{
			strcpy(cond_string, "ls");
			break;
		}

		case 0b1010:
		{
			strcpy(cond_string, "ge");
			break;
		}

		case 0b1011:
		{
			strcpy(cond_string, "lt");
			break;
		}

		case 0b1100:
		{
			strcpy(cond_string, "gt");
			break;
		}

		case 0b1101:
		{
			strcpy(cond_string, "le");
			break;
		}

		case 0b1110:
		{
			strcpy(cond_string, "al");
			break;
		}

		case 0b1111:
		{
			strcpy(cond_string, "nv");
			break;
		}
	}

	return cond_string;
}

char *decode_shift(int shift)
{
	static char shift_operation[4] = { 0 };
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

	return shift_operation;
}

int32_t swap_int32(int value)
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

	static char cpu_info[128] = { 0 };
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

static char *load_command_strings[] =
{
	"LC_SEGMENT", "LC_SYMTAB", "LC_SYMSEG", "LC_THREAD", "LC_UNIXTHREAD", "LC_LOADFVMLIB", "LC_IDFVMLIB", "IC_IDENT", "LC_FVMFILE",
	"LC_PREPAGE", "LC_DYSYMTAB", "LD_LOAD_DYLIB", "LC_ID_DYLIB", "LC_LOAD_DYLINKER", "LC_ID_DYLINKER", "LC_PREBOUND_DYLIB",
	"LC_ROUTINES", "LC_SUB_FRAMEWORKS", "LC_SUB_UMBRELLA", "LC_SUB_CLIENT", "LC_SUB_LIBRARY", "LC_TWOLEVEL_HINTS", "LC_PREBIND_CKSUM",
	"LC_LOAD_WEAK_DYLIB", "LC_SEGMENT_64", "LC_ROUTINES_64", "LC_UUID", "LC_RPATH", "LC_CODE_SIGNATURE", "LC_SEGMENT_SPLIT_INFO",
	"LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_ENCRYPTION_INFO", "LC_DYLD_INFO", "LC_LOAD_UPWARD_DYLIB", "LC_VERSION_MIN_MAXOSX",
	"LC_VERSION_MIN_IPHONEOS", "LC_FUNCTION_STARTS", "LC_DYLD_ENVIRONMENT", "LC_MAIN", "LC_DATA_IN_CODE", "LC_SOURCE_VERSION",
	"LC_DYLIB_CODE_SIGN_DRS", "LC_ENCRYPTION_INFO_64", "LC_LINKER_OPTION", "LC_LINKER_OPTIMIZATION_HINT", "LC_VERSION_MIN_TVOS",
	"LC_VERSION_MIN_WATCHOS", "LC_NOTE", "LC_BUILD_VERSION", "LC_DYLD_EXPORTS_TRIE", "LC_DYLD_CHAINED_FIXUPS"
};

const char *load_command_string(uint32_t cmd)
{
	if (cmd == 0x80000000)
		return "LC_REQ_DYLD";

	if (cmd == (0x22 | 0x80000000))
			return "LC_DYLD_INFO_ONLY";

	if ((cmd & 0x80000000) == 0x80000000)
		cmd = cmd & ~0x80000000;

	if (cmd < 0x0 || cmd > 0x34)
		return "unknown";

	return load_command_strings[cmd - 1];
}