#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include "utils.h"

extern uint32_t segment_count;
extern uint32_t section_count;

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

uint64_t read_uint64_t(FILE *file, int offset)
{
	uint64_t r;
	fseek(file, offset, SEEK_SET);
	fread(&r, sizeof(uint64_t), 1, file);
	return r;
}

uint64_t read_uleb128(uint8_t *data, uint64_t *end)
{
	uint32_t offset = *end;
	uint8_t byte = data[offset++];

	uint64_t result = byte & 0x7f;
	uint8_t shift = 7;

	while (byte & 0x80)
	{
		byte = data[offset++];
		result |= (byte & 0x7f) << shift;
		shift += 7;
	}

	*end = offset;
	return result;
}

void read_string(FILE *file, int offset, char *buffer, int buffer_size)
{
	*buffer = '\0';
	int c = 0;
	
	fseek(file, offset, SEEK_SET);

	while ((c = fgetc(file)) != '\0' && c != EOF && c < buffer_size)
	{
		strcat(buffer, (char *)&c);
		c++;
	}
}

char *read_string_v(FILE *file, int offset, char *terminator)
{
	char *buffer = malloc(1);
	int c = 0;

	*buffer = '\0';
	fseek(file, offset, SEEK_SET);

	while ((c = fgetc(file)) && c != EOF)
	{
		for (int i = 0; i < strlen(terminator) + 1; i++)
		{
			if (c == terminator[i])
				return buffer;
		}

		buffer = realloc(buffer, strlen(buffer) + 2);
		strncat(buffer, (char *)&c, strlen(buffer) + 1);
		c++;
	}

	return buffer;
}

char *read_string_vm(char *start, int *index, char *terminator)
{
	int c = 0;
	char *buffer = malloc(1);
	*buffer = '\0';

	while ((c = start[*index]))
	{
		for (int i = 0; i < strlen(terminator) + 1; i++)
		{
			if (c == terminator[i])
				return buffer;
		}

		(*index)++;

		buffer = realloc(buffer, strlen(buffer) + 2);
		strncat(buffer, (char *)&c, strlen(buffer) + 1);
	}

	return buffer;
}

void str_replace(char *target, const char *needle, const char *replacement)
{
    char buffer[1024] = {0};
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

int32_t swap_int32_t(int value)
{
    return (((value & 0x000000ff) << 24) |
			((value & 0x0000ff00) <<  8) |
			((value & 0x00ff0000) >>  8) |
			((value & 0xff000000) >> 24));
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

	static char cpu_info[128] = {0};
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
		cmd &= ~0x80000000;

	if (cmd < 0x1 || cmd > 0x34)
		return "unknown";

	return load_command_strings[cmd - 1];
}

uint64_t address_for_symbol(symbol_data_t *data, char *name)
{
	if (memcmp(name, "sub_", 4) == 0)
	{
		uint64_t address = 0;
		sscanf(name + 4, "%" PRIx64, &address);
		return address;
	}

	for (int i = 0; i < data->nsyms; i++)
	{
		symbol_t *symbol = data->symbols + i;
		
		if (strcmp(symbol->name, name) == 0)
			return symbol->offset;
	}

	return 0;
}

char *symbol_for_address(symbol_data_t *data, uint64_t address)
{
	for (int i = 0; i < data->nsyms; i++)
	{
		symbol_t *symbol = data->symbols + i;
		
		if (symbol->offset == address)
		{
			char *name = malloc(strlen(symbol->name) + 1);
			strcpy(name, symbol->name);
			return name;
		}
	}

	char number[17];
	snprintf(number, 16, "%" PRIx64, address);

	char *name = malloc(strlen(number) + 5);
	snprintf(name, strlen(number) + 5, "sub_%s", number);
	return name;
}

section_t *section_by_region(section_t *sections, uint64_t address)
{
	for (int i = 0; i < section_count; i++)
	{
		section_t *section = sections + i;
		
		if (address < section->offset + section->size)
			return section;
	}

	return NULL;
}

segment_t *segment_by_vmregion(segment_t *segments, uint64_t address)
{
	for (int i = 0; i < segment_count; i++)
	{
		segment_t *segment = segments + i;
		
		if (address < segment->vmaddr + segment->vmsize)
			return segment;
	}

	return NULL;
}

section_t *section_by_name(section_t *sections, const char *name)
{
	for (int i = 0; i < section_count; i++)
	{
		section_t *section = sections + i;

		if (strncmp(name, section->name, 16) == 0)
			return section;
	}

	return NULL;
}

char *path_combine(char *first, char *second)
{
	size_t size = strlen(first) + strlen(second) + 2;
	char *path = malloc(size);

	#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
	char separator = '\\';
	#else
	char separator = '/';
	#endif

	snprintf(path, size, "%s%c%s", first, separator, second);
	return path;
}

uint64_t correct_offset(uint64_t offset, segment_t *segments)
{
	if (segment_count < 2)
		return offset;

	return offset - segments[1].vmaddr;
}