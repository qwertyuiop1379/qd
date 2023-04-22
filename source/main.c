#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <inttypes.h>
#include "utils.h"
#include "mach-o.h"
#include "disassemble.h"
#include "demangle.h"
#include "objc.h"

#define HELP_MESSAGE \
	"\n"\
	"qd: v1.0.0 - by qwertyuiop1379\n"\
	"Cross platform mach-o tool and armv8.6 disassembler\n"\
	"\n"\
	CCYAN "Usage" CDEFAULT "\n"\
	"\t%1$s [options...] <mach-o file> : inspect mach-o file\n"\
	"\t%1$s -i <instruction> : disassemble single instruction\n"\
	"\n"\
	CCYAN "Mach-O info options" CDEFAULT "\n"\
	"\t-a <arch> : select architecture -- required for operations on fat files\n"\
	"\t-c : print load commands\n"\
	"\t-o : print segments and sections\n"\
	"\t-S : print cstrings\n"\
	"\t-l : print linked libraries\n"\
	"\t--extract : extract architecture from binary (specify with -a <arch>)\n"\
	"\n"\
	CCYAN "Signing options" CDEFAULT "\n"\
	"\t-e : print entitlements\n"\
	"\t-p : add platform-application entitlement" CRED " (not implemented)" CDEFAULT "\n"\
	"\t-b <entitlements> : sign with entitlements" CRED " (not implemented)" CDEFAULT "\n"\
	"\t-D <output file> : dump entitlements to file\n"\
	"\n"\
	CCYAN "Disassembler options" CDEFAULT "\n"\
	"\t-d <symbol> : print disassembly for symbol. use '.' for entire __text section\n"\
	"\t-f : print function info\n"\
	"\t-s : print symbols\n"\
	"\n"\
	CCYAN "Objective-C options" CDEFAULT "\n"\
	"\t-h <output> : dump headers to folder\n"\
	"\n"\

uint32_t segment_count;
uint32_t section_count;

int main(int argc, char **argv, char **envp)
{
	bool has_op = false;

	bool show_commands = false;
	bool show_macho = false;
	bool show_disassembly = false;
	bool show_functions = false;
	bool show_strings = false;
	bool show_symbols = false;
	bool show_links = false;
	bool show_entitlements = false;
	bool platformize_binary = false;
	bool sign_binary = false;
	bool dump_entitlements = false;
	bool dump_headers = false;
	bool extract_arch = false;

	char *filename = {0};
	char *disassemble_symbol = {0};
	char *ent_filename = {0};
	char *header_output = {0};
	struct cpu *cpu = NULL;

	if (argc < 2)
	{
		printf(HELP_MESSAGE, argv[0]);
		return 1;
	}

	for (int a = 1; a < argc; a++)
	{
		char *arg = argv[a];

		if (*arg == '-')
		{
			if (argc < 3)
			{
				printf(HELP_MESSAGE, argv[0]);
				return 1;
			}

			switch (arg[1])
			{
				case 'i':
				case 'a':
				case 'd':
				case 'b':
				case 'D':
				case 'h':
				{
					if (a + 1 >= argc)
					{
						err("Option '%s' requires paramter but none is passed.\n", arg);
						return 1;
					}
				}
			}
			
			switch (arg[1])
			{
				case 'i':
				{
					uint32_t instruction = strtoul(argv[a + 1], 0, 16);
					char asm_output[512];

					decode_context_t context;
					context.integer_style = 0;
					context.float_style = 0;
					context.instruction = swap_int32_t(instruction);
					context.decode_string = asm_output;
					context.pc = 0;

					symbol_data_t data;
					data.symbols = NULL;
					data.nsyms = 0;
					context.symbol_data = &data;

					if (disassemble_master(&context))
						printf("" CCYAN "%08x" CDEFAULT ": " CYELLOW "%s\n" CDEFAULT, instruction, context.decode_string);
					else
						printf("" CCYAN "%08x" CDEFAULT ": " CRED "Unknown instruction " CDEFAULT "(%d)\n", instruction, context.group);

					return 0;
				}

				case 'a':
				{
					if (cpu)
					{
						err("Please only select one architecture.\n");
						return 1;
					}
					
					if (!(cpu = cpu_for_name(argv[a + 1])))
					{
						err("CPU type '%s' is not supported.\n", argv[a + 1]);
						return 1;
					}

					a++;
					continue;
				}

				case 'd':
				{
					has_op = true;
					disassemble_symbol = argv[++a];
					show_disassembly = true;
					continue;
				}

				case '-':
				{
					if (!strcmp(arg + 2, "extract"))
					{
						has_op = true;
						extract_arch = true;
						continue;
					}

					err("Unknown argument '%s'.\n", arg);
					return 1;
				}

				case 'c': has_op = true; show_commands = true; continue;
				case 'o': has_op = true; show_macho = true; continue;
				case 's': has_op = true; show_symbols = true; continue;
				case 'f': has_op = true; show_functions = true; continue;
				case 'S': has_op = true; show_strings = true; continue;
				case 'l': has_op = true; show_links = true; continue;
				case 'e': has_op = true; show_entitlements = true; continue;
				case 'p': has_op = true; platformize_binary = true; continue;
				case 'b': has_op = true; sign_binary = true; ent_filename = argv[++a]; continue;
				case 'D': has_op = true; dump_entitlements = true; ent_filename = argv[++a]; continue;
				case 'h': has_op = true; dump_headers = true; header_output = argv[++a]; continue;

				default:
				{
					err("Unknown argument '%s'.\n", arg);
					return 1;
				}
			}
		}
		else
		{
			if (filename)
			{
				err("Too many arguments passed.\n");
				return 1;
			}

			filename = malloc(sizeof(char) * (strlen(arg) + 1));
			*filename = '\0';

			strcpy(filename, arg);
		}
	}

	if (strlen(filename) == 0)
	{
		printf(HELP_MESSAGE, argv[0]);
		return 1;
	}

	FILE *file = fopen(filename, "r+");

	if (!file)
	{
		err("Failed to open file '%s'. Exiting.\n", filename);
		return 1;
	}

	uint32_t magic = read_uint32_t(file, 0);
	bool is_fat = (magic == FAT_MAGIC || magic == FAT_CIGAM);
	bool should_swap = (magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM);
	bool is_64_bit;

	if (!has_op && (cpu || !is_fat))
	{
		err("Please choose an operation.\n");
		return 1;
	}

	int header_size;
	int ncmds;
	int load_command_offset;
	int nfat_arch;

	uint32_t *arch_offsets;

	if (is_fat)
	{
		header_size = sizeof(struct fat_header);
		int arch_size = sizeof(struct fat_arch);
		struct fat_header *header = read_bytes(file, 0, header_size);

		if (should_swap)
			swap_fat_header(header, 0);

		int arch_offset = header_size;
		nfat_arch = header->nfat_arch;

		arch_offsets = malloc(sizeof(int) * nfat_arch);

		for (int i = 0; i < nfat_arch; i++)
		{
			struct fat_arch *arch = read_bytes(file, arch_offset, arch_size);

			if (should_swap)
				swap_fat_arch(arch, 1, 0);

			if (extract_arch)
			{
				if (cpu && cpu->cpu_type == arch->cputype && (cpu->cpu_subtype == arch->cpusubtype || cpu->cpu_subtype == CPU_SUBTYPE_MULTIPLE))
				{
					const char *arch_name = name_for_cpu(cpu);
					char *new_file = malloc(strlen(filename) + strlen(arch_name) + 2);
					sprintf(new_file, "%s.%s", filename, arch_name);

					FILE *thinned = fopen(new_file, "w+");

					if (!thinned)
					{
						err("Failed to create file '%s'.\n", new_file);
						free(new_file);
						return 1;
					}

					void *buffer = malloc(arch->size);

					if (!buffer)
					{
						err("Failed to allocate buffer size. This is probably an issue with the endianness of fat_arch->size.\n");
						free(new_file);
						return 1;
					}

					printf("Extracting %s slice...\n", arch_name);
					
					fseek(file, arch->offset, SEEK_SET);
					fread(buffer, 1, arch->size, file);
					fwrite(buffer, 1, arch->size, thinned);

					fclose(thinned);
					free(buffer);

					printf("Successfully extracted %s slice to '%s'.\n", arch_name, new_file);
						
					free(new_file);
					return 0;
				}
			}

			arch_offsets[i] = arch->offset;
			arch_offset += arch_size;

			free(arch);
		}
		
		free(header);
	}
	else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_CIGAM)
	{
		if (extract_arch)
		{
			err("File is not fat, cannot extract arch.\n");
			return 1;
		}

		nfat_arch = 1;
		arch_offsets = malloc(sizeof(int));
		arch_offsets[0] = 0;
	}
	else
	{
		err("File does not look like a mach-o or FAT binary.\n");
		return 1;
	}

	bool cpu_found = false;

	if (is_fat && !cpu)
		printf("FAT file has %d architectures:\n", nfat_arch);

	for (int a = 0; a < nfat_arch; a++)
	{
		magic = read_uint32_t(file, arch_offsets[a]);
		should_swap = (magic == MH_CIGAM || magic == MH_CIGAM_64);
		is_64_bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
		
		struct cpu header_cpu;

		if (is_64_bit)
		{
			header_size = sizeof(struct mach_header_64);
			struct mach_header_64 *header = read_bytes(file, arch_offsets[a], header_size);

			header_cpu.cpu_type = header->cputype;
			header_cpu.cpu_subtype = header->cpusubtype;

			if (should_swap)
				swap_mach_header_64(header, 0);

			ncmds = header->ncmds;
			load_command_offset = header_size + arch_offsets[a];

			free(header);
		}
		else
		{
			header_size = sizeof(struct mach_header);
			struct mach_header *header = read_bytes(file, arch_offsets[a], header_size);

			header_cpu.cpu_type = header->cputype;
			header_cpu.cpu_subtype = header->cpusubtype;

			if (should_swap)
				swap_mach_header(header, 0);

			ncmds = header->ncmds;
			load_command_offset = header_size + arch_offsets[a];

			free(header);
		}

		const char *cpu_name = name_for_cpu(&header_cpu);

		if (!cpu && nfat_arch > 1)
		{
			printf("-" CCYAN "%s" CDEFAULT " (offset 0x%x)\n", cpu_name, arch_offsets[a]);
			continue;
		}

		if (cpu && cpu->cpu_type == header_cpu.cpu_type && (cpu->cpu_subtype == header_cpu.cpu_subtype || cpu->cpu_subtype == CPU_SUBTYPE_MULTIPLE))
			cpu_found = true;
		else if (nfat_arch > 1)
			continue;

		if (!has_op)
		{
			err("Please choose an operation.\n");
			return 1;
		}

		uint32_t lc_symtab_offset = 0;
		uint32_t lc_dysymtab_offset = 0;
		uint32_t lc_linkedit_offset = 0;
		uint32_t lc_dyld_offset = 0;
		uint32_t lc_function_starts_offset = 0;

		segment_t *segments = malloc(0);
		section_t *sections = malloc(0);

		uint32_t *library_offsets = malloc(0);
		uint32_t library_count = 0;

		uint32_t dylib_id_offset = 0;

		printf("Mach header at file offset: 0x%" PRIx32 "\n", arch_offsets[a]);

		if (show_commands)
			printf("\n  Reading load commands...\n\n");

		for (int i = 0; i < ncmds; i++)
		{
			struct load_command *cmd = read_bytes(file, load_command_offset, sizeof(struct load_command));
			
			if (should_swap)
				swap_load_command(cmd, 0);

			if (show_commands)
				printf("LC <0x%03x - 0x%03x>: %s (0x%x)\n", load_command_offset - arch_offsets[a], load_command_offset + cmd->cmdsize - arch_offsets[a], load_command_string(cmd->cmd), cmd->cmd);

			switch (cmd->cmd)
			{
				case LC_SEGMENT:
				{
					struct segment_command *segment = read_bytes(file, load_command_offset, sizeof(struct segment_command));

					if (should_swap)
						swap_segment_command(segment, 0);

					segments = realloc(segments, sizeof(segment_t) * (segment_count + 1));

					strncpy(segments[segment_count].name, segment->segname, 16);
					segments[segment_count].offset = segment->fileoff;
					segments[segment_count].size = segment->filesize;
					segments[segment_count].vmaddr = segment->vmaddr;
					segments[segment_count++].vmsize = segment->vmsize;

					if (show_macho)
						printf("\nSegment %d <0x%06x - 0x%06x>: " CRED "%.16s" CDEFAULT ": " CGREEN "%d" CDEFAULT " sections\n", i + 1, segment->fileoff, segment->fileoff + segment->filesize, segment->segname, segment->nsects);
					
					int section_offset = load_command_offset + sizeof(struct segment_command);

					for (int s = 0; s < segment->nsects; s++)
					{
						struct section *section = read_bytes(file, section_offset, sizeof(struct section));

						sections = realloc(sections, sizeof(section_t) * (section_count + 1));
						
						strncpy(sections[section_count].name, section->sectname, 16);
						sections[section_count].offset = section->offset;
						sections[section_count].index = segment_count + 1;
						sections[section_count++].size = section->size;

						if (show_macho)
							printf("\t<0x%06x - 0x%06x>: " CMAGENTA "%.16s" CDEFAULT "\n", section->offset, section->offset + section->size, section->sectname);
							
						section_offset += sizeof(struct section);
						free(section);
					}
					
					free(segment);
					break;
				}
				
				case LC_SEGMENT_64:
				{
					struct segment_command_64 *segment = read_bytes(file, load_command_offset, sizeof(struct segment_command_64));

					if (should_swap)
						swap_segment_command_64(segment, 0);

					segments = realloc(segments, sizeof(segment_t) * (segment_count + 1));

					strncpy(segments[segment_count].name, segment->segname, 16);
					segments[segment_count].offset = segment->fileoff;
					segments[segment_count].size = segment->filesize;
					segments[segment_count].vmaddr = segment->vmaddr;
					segments[segment_count++].vmsize = segment->vmsize;

					if (show_macho)
						printf("\nSegment %d <0x%06" PRIx64 " - 0x%06" PRIx64 ">: " CRED "%.16s" CDEFAULT ": " CGREEN "%d" CDEFAULT " sections\n", i + 1, segment->fileoff, segment->fileoff + segment->filesize, segment->segname, segment->nsects);
					
					int section_offset = load_command_offset + sizeof(struct segment_command_64);

					for (int s = 0; s < segment->nsects; s++)
					{
						struct section_64 *section = read_bytes(file, section_offset, sizeof(struct section_64));

						sections = realloc(sections, sizeof(section_t) * (section_count + 1));
						
						strncpy(sections[section_count].name, section->sectname, 16);
						sections[section_count].offset = section->offset;
						sections[section_count].index = segment_count + 1;
						sections[section_count++].size = section->size;

						if (show_macho)
							printf("\t<0x%06x - 0x%06" PRIx64 ">: " CMAGENTA "%.16s" CDEFAULT "\n", section->offset, section->offset + section->size, section->sectname);
							
						section_offset += sizeof(struct section_64);
						free(section);
					}
					
					free(segment);
					break;
				}

				case LC_SYMTAB:
				{
					lc_symtab_offset = load_command_offset;
					break;
				}

				case LC_DYSYMTAB:
				{
					lc_dysymtab_offset = load_command_offset;
					break;
				}

				case LC_CODE_SIGNATURE:
				{
					lc_linkedit_offset = load_command_offset;
					break;
				}

				case LC_DYLD_INFO:
				case LC_DYLD_INFO_ONLY:
				{
					lc_dyld_offset = load_command_offset;
					break;
				}

				case LC_FUNCTION_STARTS:
				{
					lc_function_starts_offset = load_command_offset;
					break;
				}

				case LC_ID_DYLIB:
				{
					dylib_id_offset = load_command_offset;
					break;
				}

				case LC_LOAD_DYLIB:
				case LC_LOAD_WEAK_DYLIB:
				case LC_REEXPORT_DYLIB:
				{
					library_offsets = realloc(library_offsets, sizeof(int) * library_count + 1);
					library_offsets[library_count++] = load_command_offset;

					break;
				}
			}

			load_command_offset += cmd->cmdsize;
			free(cmd);
		}

		uint64_t mach_end = 0;

		if (segment_count)
		{
			segment_t segment = segments[segment_count - 1];
			mach_end = arch_offsets[a] + segment.offset + segment.size;
		}

		// Generate symbol data

		symbol_data_t symbol_data;
		symbol_data.symbols = malloc(0);
		symbol_data.nsyms = 0;

		if (lc_symtab_offset)
		{
			struct symtab_command *symtab = read_bytes(file, lc_symtab_offset, sizeof(struct symtab_command));

			if (should_swap)
				swap_symtab_command(symtab, 0);

			char *stab = read_bytes(file, arch_offsets[a] + symtab->stroff, symtab->strsize);

			if (is_64_bit)
			{
				struct nlist_64 *symbols = read_bytes(file, arch_offsets[a] + symtab->symoff, sizeof(struct nlist_64) * symtab->nsyms);

				for (int i = 0; i < symtab->nsyms; i++)
				{
					struct nlist_64 *symbol = symbols + i;

					if ((symbol->n_type & N_SECT) == N_SECT && symbol->n_sect)
					{
						char *name = stab + symbol->n_un.n_strx;

						if (strlen(name))
						{
							symbol_data.symbols = realloc(symbol_data.symbols, sizeof(symbol_t) * (symbol_data.nsyms + 1));
							strncpy(symbol_data.symbols[symbol_data.nsyms].name, name, 255);
							symbol_data.symbols[symbol_data.nsyms].offset = symbol->n_value;
							symbol_data.symbols[symbol_data.nsyms++].section = symbol->n_sect;
						}
					}
				}

				free(symbols);
			}
			else
			{
				struct nlist *symbols = read_bytes(file, arch_offsets[a] + symtab->symoff, sizeof(struct nlist) * symtab->nsyms);

				for (int i = 0; i < symtab->nsyms; i++)
				{
					struct nlist *symbol = symbols + i;

					if ((symbol->n_type & N_SECT) == N_SECT && symbol->n_sect)
					{
						char *name = stab + symbol->n_un.n_strx;

						if (strlen(name))
						{
							symbol_data.symbols = realloc(symbol_data.symbols, sizeof(symbol_t) * (symbol_data.nsyms + 1));
							strncpy(symbol_data.symbols[symbol_data.nsyms].name, name, 255);
							symbol_data.symbols[symbol_data.nsyms].offset = symbol->n_value;
							symbol_data.symbols[symbol_data.nsyms++].section = symbol->n_sect;
						}
					}
				}

				free(symbols);
			}
			
			symbol_data.sym = symtab;
		}

		if (lc_dysymtab_offset)
		{
			symbol_data.dysym = read_bytes(file, lc_dysymtab_offset, sizeof(struct dysymtab_command));
		}

		if (lc_dyld_offset)
		{
			struct dyld_info_command *dyld = read_bytes(file, lc_dyld_offset, sizeof(struct dyld_info_command));

			uint32_t offset = dyld->lazy_bind_off;
			uint32_t size = dyld->lazy_bind_size;
			
			stub_t *stubs = malloc(0);
			int stub_count = 0;

			uint8_t *bind_table = read_bytes(file, arch_offsets[a] + offset, size);
			uint64_t index = 0;

			char *name = NULL;
			int32_t segment = 0;
			uint32_t segment_offset = 0;
			uint32_t library = 0;
			uint8_t width = is_64_bit ? 8 : 4;

			while (index < size)
			{
				uint8_t instruction = bind_table[index++];
				uint8_t op = instruction >> 4;
				uint8_t imm = instruction & 0xf;

				switch (op)
				{
					case BIND_OPCODE_DONE:
					{
						break;
					}

					case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
					{
						library = imm;
						break;
					}

					case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
					{
						library = read_uleb128(bind_table, &index);
						break;
					}

					case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
					{
						library = -(int8_t)imm;
						break;
					}

					case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
					{
						name = (char *)(bind_table + index);
						index += strlen(name) + 1;
						break;
					}

					case BIND_OPCODE_SET_TYPE_IMM:
					{
						break;
					}

					case BIND_OPCODE_SET_ADDEND_SLEB:
					{
						read_uleb128(bind_table, &index);
						break;
					}

					case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
					{
						segment = imm;
						segment_offset = read_uleb128(bind_table, &index);
						break;
					}

					case BIND_OPCODE_ADD_ADDR_ULEB:
					{
						segment_offset += read_uleb128(bind_table, &index);
						break;
					}

					case BIND_OPCODE_DO_BIND:
					{
						uint32_t offset = read_uint32_t(file, arch_offsets[a] + segments[segment].offset + segment_offset);

						stubs = realloc(stubs, sizeof(stub_t) * (stub_count + 1));
						stubs[stub_count].offset = offset;
						stubs[stub_count].segment = segment;
						stubs[stub_count].library = library;
						stubs[stub_count++].name = name;

						break;
					}

					case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
					{
						uint32_t offset = read_uint32_t(file, arch_offsets[a] + segments[segment].offset + segment_offset);
						
						stubs = realloc(stubs, sizeof(stub_t) * (stub_count + 1));
						stubs[stub_count].offset = offset;
						stubs[stub_count].segment = segment;
						stubs[stub_count].library = library;
						stubs[stub_count++].name = name;

						segment_offset += read_uleb128(bind_table, &index);
						break;
					}

					case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
					{
						uint32_t offset = read_uint32_t(file, arch_offsets[a] + segments[segment].offset + segment_offset);
						
						stubs = realloc(stubs, sizeof(stub_t) * (stub_count + 1));
						stubs[stub_count].offset = offset;
						stubs[stub_count].segment = segment;
						stubs[stub_count].library = library;
						stubs[stub_count++].name = name;

						segment_offset += imm * width;
						break;
					}

					case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
					{
						int count = read_uleb128(bind_table, &index);
						int skip = read_uleb128(bind_table, &index);

						for (int i = 0; i < count; i++)
						{
							uint32_t offset = read_uint32_t(file, arch_offsets[a] + segments[segment].offset + segment_offset);
							
							stubs = realloc(stubs, sizeof(stub_t) * (stub_count + 1));
							stubs[stub_count].offset = offset;
							stubs[stub_count].segment = segment;
							stubs[stub_count].library = library;
							stubs[stub_count++].name = name;

							segment_offset += width + skip;
						}

						break;
					}

					case BIND_OPCODE_THREADED:
					{
						switch (imm)
						{
							case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
							{
								read_uleb128(bind_table, &index);
								break;
							}

							case BIND_SUBOPCODE_THREADED_APPLY:
							{
								break;
							}

							default:
							{
								printf("bad subopcode 0x%x\n", imm);
								break;
							}
						}

						break;
					}

					default:
					{
						printf("bad opcode 0x%x\n", op);
						break;
					}
				}
			}

			section_t *section = section_by_name(sections, "__stubs");

			if (section)
			{
				uint32_t stub_offset = section->offset;

				for (int i = 0; i < section->size / 12; i++)
				{
					uint32_t ldr = read_uint32_t(file, arch_offsets[a] + stub_offset + 4);
					uint32_t la_symbol_ptr_addr = stub_offset + (sign_extend(masks(ldr, 0b1111111111111111111, 5), 19) * 4) + 4;
					uint64_t helper_addr = read_uint64_t(file, arch_offsets[a] + la_symbol_ptr_addr);

					for (int s = 0; s < stub_count; s++)
					{
						stub_t *stub = stubs + s;

						if (stub->offset == helper_addr)
						{
							symbol_data.symbols = realloc(symbol_data.symbols, sizeof(symbol_t) * (symbol_data.nsyms + 1));
							strncpy(symbol_data.symbols[symbol_data.nsyms].name, stub->name, 255);
							symbol_data.symbols[symbol_data.nsyms].offset = stub_offset;
							symbol_data.symbols[symbol_data.nsyms++].section = section->index;
						}
					}

					stub_offset += 12;
				}
			}

			free(stubs);
			free(bind_table);
			free(dyld);
		}

		// Mach-O options

		if (show_strings)
		{
			section_t *section = section_by_name(sections, "__cstring");

			if (!section)
			{
				err("Failed to find __cstring.\n");
				return 1;
			}

			printf("\n  Finding strings...\n\n");

			int offset = arch_offsets[a] + section->offset;
			while (offset < (arch_offsets[a] + section->offset + section->size))
			{
				char string[1024] = {0};
				read_string(file, offset, string, 1024);

				int size = strlen(string) * sizeof(char);
				str_replace(string, "\n", "\\n");
				str_replace(string, "\t", "\\t");

				if (strlen(string))
					printf("%s\n", string);

				offset += size ?: sizeof(char);
			}
		}

		if (show_links)
		{
			printf("\n  Reading linked libraries...\n\n");

			for (int l = 0; l < library_count; l++)
			{
				struct dylib_command *dylib = read_bytes(file, library_offsets[l], sizeof(struct dylib_command));

				char dylib_name[1024] = {0};
				read_string(file, library_offsets[l] + dylib->dylib.name.offset, dylib_name, 1024);

				printf("Dynamic Link: '" CYELLOW "%s" CDEFAULT "'\n", dylib_name);
				free(dylib);
			}
		}

		// Signing options

		if (show_entitlements || dump_entitlements || sign_binary)
		{
			if (!lc_linkedit_offset)
			{
				err("File does not have a linkedit section?.\n");
				return 1;
			}

			if (((show_entitlements || dump_entitlements) && sign_binary))
			{
				err("You cannot read and write entitlements at the same time.\n");
				return 1;
			}

			struct linkedit_data_command *linkedit = read_bytes(file, lc_linkedit_offset, sizeof(struct linkedit_data_command));
			struct SuperBlob *super_blob = read_bytes(file, arch_offsets[a] + linkedit->dataoff, linkedit->datasize);

			// if (should_swap)
				swap_super_blob(super_blob);

			bool found = false;
			for (int i = 0; i < super_blob->count; i++)
			{
				uint32_t type = mask(super_blob->index[i], 0xffffffff);
				if (type == 5)
				{
					found = true;
					int blob_offset = arch_offsets[a] + linkedit->dataoff + masks(super_blob->index[i], 0xffffffff, 32) + 0x14;

					if (sign_binary)
					{
						FILE *input = fopen(ent_filename, "r");

						if (!input)
						{
							err("Could open file '%s'.\n", ent_filename);
							return 1;
						}

						fseek(input, 0, SEEK_END);

						int size = ftell(input) + 1;

						ftruncate(fileno(file), blob_offset + size);

						char *entitlements = calloc(size, sizeof(char));
						read_string(input, 0, entitlements, size);

						fclose(input);

						fseek(file, blob_offset, SEEK_SET);
						fwrite(entitlements, sizeof(char), size, file);
						
						free(entitlements);
						printf("Successfully signed '%s' with entitlements.\n", filename);
					}
					else
					{
						char entitlements[1024] = {0};
						read_string(file, blob_offset, entitlements, 1024);

						if (show_entitlements)
							printf("\n  Reading entitlements...\n\n%s\n", entitlements);
						
						if (dump_entitlements)
						{
							FILE *output = fopen(ent_filename, "w");

							if (!output)
							{
								err("Could write to output file '%s'.\n", ent_filename);
								return 1;
							}

							fwrite(entitlements, sizeof(char), strlen(entitlements), output);
							fclose(output);

							printf("Entitlements written to file '%s'.\n", ent_filename);
						}
					}
				}
			}

			if (!found)
			{
				err("File does not contain a code signature.\n");
				return 1;
			}

			free(super_blob);
			free(linkedit);
		}
		
		// Disassembler options

		if (show_disassembly)
		{
			uint64_t dissassemble_address;
			bool is_section;

			if (strcmp(disassemble_symbol, ".") == 0)
			{
				dissassemble_address = section_by_name(sections, "__text")->offset;
				is_section = 1;
			}
			else
			{
				dissassemble_address = address_for_symbol(&symbol_data, disassemble_symbol);
				is_section = 0;
			}

			if (!dissassemble_address)
			{
				err("Failed to find symbol '%s'.\n", disassemble_symbol);
				return 1;
			}

			// if (!lc_function_starts_offset)
			// {
			// 	err("Failed to get function info.\n");
			// 	return 1;
			// }

			uint64_t dissassemble_end;
			bool found = is_section;

			uint64_t *functions = malloc(0);
			uint32_t function_count = 0;

			if (lc_function_starts_offset)
			{
				struct linkedit_data_command *linkedit = read_bytes(file, lc_function_starts_offset, sizeof(struct linkedit_data_command));
				uint8_t *data = read_bytes(file, arch_offsets[a] + linkedit->dataoff, linkedit->datasize);

				uint64_t address_start = 0;
				uint64_t end = 0;

				while (end < linkedit->datasize)
				{
					address_start += read_uleb128(data, &end);

					if (!function_count || address_start != functions[function_count - 1])
					{
						functions = realloc(functions, sizeof(function_t) * (function_count + 1));
						functions[function_count++] = address_start;
					}
					
					if (address_start == dissassemble_address && !is_section)
					{
						dissassemble_end = address_start + read_uleb128(data, &end);
						found = 1;
					}
				}

				free(data);
				free(linkedit);
			}

			if (is_section)
			{
				section_t *section = section_by_name(sections, "__text");
				dissassemble_end = section->offset + section->size;
				found = 1;
			}

			if (!found)
			{
				err("Failed to find symbol '%s'.\n", disassemble_symbol);
				return 1;
			}

			uint32_t ninstructions = (dissassemble_end - dissassemble_address) / 4;
			uint32_t *instructions = read_bytes(file, arch_offsets[a] + dissassemble_address, dissassemble_end - dissassemble_address);

			char asm_output[512] = {0};

			decode_context_t context;
			context.integer_style = 0;
			context.float_style = 0;
			context.decode_string = asm_output;
			context.symbol_data = &symbol_data;
			context.pc = dissassemble_address;

			char *name = section_by_region(sections, dissassemble_address)->name;

			for (int i = 0; i < ninstructions; i++)
			{
				uint32_t instruction = instructions[i];
				
				context.instruction = instruction;
				context.pc += 4;

				for (int i = 0; i < function_count; i++)
				{
					uint64_t function = functions[i];

					if (function == context.pc)
					{
						char *symbol = symbol_for_address(&symbol_data, function);
						char *demangled = demangle_symbol(symbol);

						printf(CGREEN "%.16s:0x%016" PRIx64 CDEFAULT "\n", name, function);
						printf(CGREEN "%.16s:0x%016" PRIx64 CDEFAULT " %s%s%s\n", name, function, symbol, demangled ? "  ;  " : "", demangled ?: "");
						printf(CGREEN "%.16s:0x%016" PRIx64 CDEFAULT "\n", name, function);

						free(demangled);
					}
				}

				if (disassemble_master(&context))
					printf(CGREEN "%.16s:0x%016" PRIx64 CDEFAULT "    " CYELLOW "%s\n" CDEFAULT, name, context.pc, context.decode_string);
				else
					printf(CGREEN "%.16s:0x%016" PRIx64 CDEFAULT "    .long " CYELLOW "0x%08x" CDEFAULT " (%d)\n", name, context.pc, swap_int32_t(instruction), context.group);
			}

			free(instructions);
		}

		if (show_functions)
		{
			if (!lc_function_starts_offset)
			{
				err("Failed to get function_starts info.\n");
				return 1;
			}

			struct linkedit_data_command *linkedit = read_bytes(file, lc_function_starts_offset, sizeof(struct linkedit_data_command));
			uint8_t *data = read_bytes(file, arch_offsets[a] + linkedit->dataoff, linkedit->datasize);

			uint64_t address_start = 0;
			uint64_t end = 0;

			while (end < linkedit->datasize)
			{
				address_start += read_uleb128(data, &end);

				char *symbol = symbol_for_address(&symbol_data, address_start);
				printf(CGREEN "%.16s:0x%016" PRIx64 CDEFAULT " %s\n", section_by_region(sections, address_start)->name, address_start, symbol);
				free(symbol);
			}

			free(data);
			free(linkedit);
		}

		if (show_symbols)
		{
			printf("\n  Reading %d symbols...\n\n", symbol_data.nsyms);

			if (symbol_data.symbols)
			{
				for (int i = 0; i < symbol_data.nsyms; i++)
				{
					symbol_t *symbol = symbol_data.symbols + i;
					printf(CGREEN "%.16s:0x%016" PRIx64 CDEFAULT " %s\n", sections[symbol->section - 1].name, symbol->offset, symbol->name);
				}
			}
			else
			{
				err("Failed to find symbols.\n");
				return 1;
			}
		}

		// Objective-C options

		if (dump_headers)
		{
			objc_dump_headers(header_output, dylib_id_offset, mach_end, filename, file, sections, is_64_bit, arch_offsets, segments, &symbol_data);
		}

		free(segments);
		free(sections);
		free(library_offsets);
		free(symbol_data.symbols);
		free(symbol_data.dysym);
		free(symbol_data.sym);
	}

	if (cpu && !cpu_found)
	{
		err("File does not contain architecture '%s'\n", name_for_cpu(cpu));
		return 1;
	}

	free(filename);
	free(arch_offsets);
	fclose(file);

	return 0;
}