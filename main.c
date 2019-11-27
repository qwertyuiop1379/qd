#include "defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include "mach-o.h"
#include "utils.h"

#define HELP_MESSAGE "qd: v1.0.0 - by qwertyuiop1379\n\n"\
					"Usage:\n"\
					"\t%1$s [options...] <mach-o file> : inspect mach-o file\n"\
					"\t%1$s -i <arm64 instruction> : disassemble arm64 instruction\n"\
					"\n"\
					"Options:\n"\
					"\t-a <arch>: choose architecture -- " CRED "required for operations on multi-arch files\n" CDEFAULT \
					"\t-o : show mach-o information\n"\
					"\t-s : print all symbols\n"\
					"\t-d : show disassembly for __text\n"\
					"\t-S : print all strings\n"\
					"\t-l : print all linked libraries\n\n"

int main(int argc, char **argv, char **envp)
{
	bool show_macho = false;
	bool show_disassembly = false;
	bool show_strings = false;
	bool show_symbols = false;
	bool show_links = false;

	char *filename = NULL;

	struct cpu *cpu = NULL;

	if (argc < 2)
	{
		printf(HELP_MESSAGE, argv[0]);
		return 1;
	}

	for (int a = 1; a < argc; a++)
	{
		char *arg = argv[a];

		if (strcmp(arg, "--help") == 0)
		{
			printf(HELP_MESSAGE, argv[0]);
			return 0;
		}

		if (strcmp(arg, "-i") == 0)
		{
			if (a + 1 >= argc)
			{
				printf(HELP_MESSAGE, argv[0]);
				return 1;
			}

			uint32_t instruction = strtoul(argv[a + 1], 0, 16);
			char asm_output[128];

			disassemble(instruction, asm_output);
			printf("%s0x%08x%s: %s%s%s\n", CGREEN, instruction, CDEFAULT, strcmp(asm_output, "[unknown instruction]") == 0 ? CRED : CYELLOW, asm_output, CDEFAULT);

			return 0;
		}

		if (strcmp(arg, "-a") == 0)
		{
			if (a + 1 >= argc)
			{
				printf(HELP_MESSAGE, argv[0]);
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

		if (strcmp(arg, "-o") == 0)
		{
			if (argc < 3)
			{
				printf(HELP_MESSAGE, argv[0]);
				return 1;
			}

			show_macho = true;
			continue;
		}

		if (strcmp(arg, "-s") == 0)
		{
			if (argc < 3)
			{
				printf(HELP_MESSAGE, argv[0]);
				return 1;
			}

			show_symbols = true;
			continue;
		}

		if (strcmp(arg, "-d") == 0)
		{
			if (argc < 3)
			{
				printf(HELP_MESSAGE, argv[0]);
				return 1;
			}

			show_disassembly = true;
			continue;
		}

		if (strcmp(arg, "-S") == 0)
		{
			if (argc < 3)
			{
				printf(HELP_MESSAGE, argv[0]);
				return 1;
			}

			show_strings = true;
			continue;
		}

		if (strcmp(arg, "-l") == 0)
		{
			if (argc < 3)
			{
				printf(HELP_MESSAGE, argv[0]);
				return 1;
			}

			show_links = true;
			continue;
		}


		filename = malloc(sizeof(char) * (strlen(arg) + 1));
		*filename = '\0';

		strcpy(filename, arg);
	}

	if (strcmp(filename, "") == 0)
	{
		printf(HELP_MESSAGE, argv[0]);
		return 1;
	}

	FILE *file = fopen(filename, "rb");

	if (!file)
	{
		err("Failed to open file '%s'. Exiting.\n", filename);
		return 1;
	}

	free(filename);

	uint32_t magic = read_uint32_t(file, 0);
	bool is_fat = (magic == FAT_MAGIC || magic == FAT_CIGAM);
	bool should_swap = (magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM);
	bool is_64_bit;

	int header_size;
	int ncmds;
	int load_command_offset;
	int nfat_arch;

	int *arch_offsets;

	if (is_fat)
	{
		header_size = sizeof(struct fat_header);
		int arch_size = sizeof(struct fat_arch);
		struct fat_header *header = read_bytes(file, 0, header_size);

		if (should_swap)
			swap_fat_header(header, 0);

		int arch_offset = header_size;
		nfat_arch = header->nfat_arch;

		free(header);
		printf("FAT format detected. %s%d%s architecture%s present.\n", CGREEN, nfat_arch, CDEFAULT, nfat_arch == 1 ? "" : "s");

		arch_offsets = malloc(sizeof(int) * nfat_arch);

		for (int i = 0; i < nfat_arch; i++)
		{
			struct fat_arch *arch = read_bytes(file, arch_offset, arch_size);

			if (should_swap)
				swap_fat_arch(arch, 1, 0);

			arch_offsets[i] = arch->offset;
			arch_offset += arch_size;

			free(arch);
		}
		
	}
	else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_CIGAM)
	{
		printf("Mach-o format detected. %s1%s architecture present.\n", CGREEN, CDEFAULT);
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
			printf("-%s%s%s\n", CCYAN, cpu_name, CDEFAULT);
			continue;
		}

		if (cpu && (cpu->cpu_type != header_cpu.cpu_type || cpu->cpu_subtype != header_cpu.cpu_subtype))
			continue;

		cpu_found = true;
		printf("Reading architecture %s%s%s.\n", CCYAN, cpu_name, CDEFAULT);

		int *library_offsets = malloc(0);
		int library_count = 0;

		int text_offset;
		int text_size;

		int string_offset;
		int string_size;

		int la_symbol_offset;
		int la_symbol_size;

		struct symtab_command *symtab;
		struct dysymtab_command *dysymtab;

		for (int i = 0; i < ncmds; i++)
		{
			struct load_command *cmd = read_bytes(file, load_command_offset, sizeof(struct load_command));
			
			if (should_swap)
				swap_load_command(cmd, 0);

			if (cmd->cmd == LC_SEGMENT)
			{
				struct segment_command *segment = read_bytes(file, load_command_offset, sizeof(struct segment_command));

				if (should_swap)
					swap_segment_command(segment, 0);

				if (show_macho)
					printf("\nSegment %d <0x%06x - 0x%06x>: %s%s%s: %s%d%s sections\n", i + 1, arch_offsets[a] + segment->fileoff, arch_offsets[a] + segment->fileoff + segment->filesize, CRED, segment->segname, CDEFAULT, CGREEN, segment->nsects, CDEFAULT);
				
				int section_offset = load_command_offset + sizeof(struct segment_command);

				for (int s = 0; s < segment->nsects; s++)
				{
					struct section *section = read_bytes(file, section_offset, sizeof(struct section));

					if (show_macho)
						printf("    <0x%06x - 0x%06x>: %s%s%s\n", arch_offsets[a] + section->offset, arch_offsets[a] + section->offset + section->size, CMAGENTA, section->sectname, CDEFAULT);

					if (strcmp(section->sectname, "__text") == 0)
					{
						text_offset = section->offset;
						text_size = section->size;
					}
					else if (strcmp(section->sectname, "__cstring") == 0)
					{
						string_offset = section->offset;
						string_size = section->size;
					}
					else if (strcmp(section->sectname, "__la_symbol_ptr") == 0)
					{
						la_symbol_offset = section->reserved1;
						la_symbol_size = section->size / sizeof(uint64_t);
					}
						
					section_offset += sizeof(struct section);
					free(section);
				}
				
				free(segment);
			}
			else if (cmd->cmd == LC_SEGMENT_64)
			{
				struct segment_command_64 *segment = read_bytes(file, load_command_offset, sizeof(struct segment_command_64));

				if (should_swap)
					swap_segment_command_64(segment, 0);

				if (show_macho)
					printf("\nSegment %d <0x%06llx - 0x%06llx>: %s%s%s: %s%d%s sections\n", i + 1, arch_offsets[a] + segment->fileoff, arch_offsets[a] + segment->fileoff + segment->filesize, CRED, segment->segname, CDEFAULT, CGREEN, segment->nsects, CDEFAULT);
				
				int section_offset = load_command_offset + sizeof(struct segment_command_64);

				for (int s = 0; s < segment->nsects; s++)
				{
					struct section_64 *section = read_bytes(file, section_offset, sizeof(struct section_64));

					if (show_macho)
						printf("    <0x%06x - 0x%06llx>: %s%s%s\n", arch_offsets[a] + section->offset, arch_offsets[a] + section->offset + section->size, CMAGENTA, section->sectname, CDEFAULT);

					if (strcmp(section->sectname, "__text") == 0)
					{
						text_offset = section->offset;
						text_size = section->size;
					}
					else if (strcmp(section->sectname, "__cstring") == 0)
					{
						string_offset = section->offset;
						string_size = section->size;
					}
					else if (strcmp(section->sectname, "__la_symbol_ptr") == 0)
					{
						la_symbol_offset = section->reserved1;
						la_symbol_size = section->size / sizeof(uint64_t);
					}
						
					section_offset += sizeof(struct section_64);
					free(section);
				}
				
				free(segment);
			}
			else if (cmd->cmd == LC_SYMTAB)
			{
				symtab = read_bytes(file, load_command_offset, sizeof(struct symtab_command));
			}
			else if (cmd->cmd == LC_DYSYMTAB)
			{
				dysymtab = read_bytes(file, load_command_offset, sizeof(struct dysymtab_command));
			}
			else if ((cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_ID_DYLIB))
			{
				library_offsets = realloc(library_offsets, sizeof(int) * library_count + 1);
				library_offsets[library_count++] = load_command_offset;
			}

			load_command_offset += cmd->cmdsize;
			free(cmd);
		}

		if (show_symbols)
		{
			if (!symtab || !dysymtab)
			{
				err("Failed to find symbol table.\n");
				return 1;
			}

			printf("\n  Finding symbols...\n\n");

			int indirect_offset = arch_offsets[a] + dysymtab->indirectsymoff;
			int string_offset = arch_offsets[a] + symtab->stroff;

			int *string_table = calloc(symtab->nsyms, sizeof(int) * symtab->nsyms);
			int s = 0;

			while (string_offset < arch_offsets[a] + symtab->stroff + symtab->strsize)
			{
				char string[1024] = { 0 };
				read_string(file, string_offset, string, 1024);

				string_table[s] = string_offset;

				if (strlen(string) > 0)
					string_offset += strlen(string) * sizeof(char);
				else
					string_offset += sizeof(char);
				
				s++;
			}

			printf("Lazy symbols: \n");
			for (int s = 0; s < la_symbol_size; s++)
			{
				int index = read_uint32_t(file, indirect_offset + (s + la_symbol_offset) * sizeof(uint32_t));

				if (index < symtab->nsyms)
				{
					char string[1024] = { 0 };
					read_string(file, string_table[index], string, 1024);

					if (strlen(string) > 0)
						printf("%s\n", string);
				}
			}

			printf("\nSymbols: \n");
			int symbol_offset = arch_offsets[a] + symtab->symoff;

			for (int s = 0; s < symtab->nsyms; s++)
			{
				struct nlist_64 *symbol = read_bytes(file, symbol_offset, sizeof(struct nlist_64));

				char string[1024] = { 0 };
				read_string(file, string_table[symbol->n_un.n_strx], string, 1024);

				if (strcmp(string, "") != 0)
					printf("%s [%x]\n", string, symbol->n_type);

				free(symbol);
				symbol_offset += sizeof(struct nlist_64);
			}

			printf("\n");
		}

		if (show_disassembly)
		{
			if (!text_offset || !text_size)
			{
				err("This file does not contain a __text section?\n");
				return 1;
			}

			printf("\n  Disassembling...\n\n");

			int offset = arch_offsets[a] + text_offset;
			for (int i = 0; i < text_size / sizeof(uint32_t); i++)
			{
				uint32_t instruction = read_uint32_t(file, offset);

				char asm_string[128];
				disassemble(instruction, asm_string);
				printf("%s0x%08x%s: %s%s%s\n", CGREEN, instruction, CDEFAULT, strcmp(asm_string, "[unknown instruction]") == 0 ? CRED : CYELLOW, asm_string, CDEFAULT);

				offset += sizeof(uint32_t);
			}

			// free(symbol_name);
		}

		if (show_strings)
		{
			printf("\n  Finding strings...\n\n");

			int offset = arch_offsets[a] + string_offset;
			while (offset < (arch_offsets[a] + string_offset + string_size))
			{
				char string[1024] = { 0 };
				read_string(file, offset, string, 1024);

				int size = strlen(string) * sizeof(char);
				str_replace(string, "\n", "\\n");
				str_replace(string, "\t", "\\t");

				if (strlen(string) > 0)
					printf("%s\n", string);

				offset += size > 0 ? size : sizeof(char);
			}
		}

		if (show_links)
		{
			printf("\n  Finding linked libraries...\n\n");

			for (int l = 0; l < library_count; l++)
			{
				struct dylib_command *dylib = read_bytes(file, library_offsets[l], sizeof(struct dylib_command));

				char dylib_name[1024] = { 0 };
				read_string(file, library_offsets[l] + dylib->dylib.name.offset, dylib_name, 1024);

				printf("Linked library: '%s%s%s'\n", CYELLOW, dylib_name, CDEFAULT);

				free(dylib);
			}
		}
		
		free(symtab);
		free(dysymtab);
		free(library_offsets);
	}

	if (cpu && !cpu_found)
	{
		err("File does not contain architecture '%s'\n", name_for_cpu(cpu));
		return 1;
	}

	free(arch_offsets);
	fclose(file);

	return 0;
}