#ifndef utils_h
#define utils_h

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "mach-o.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    #define CDEFAULT ""
    #define CRED ""
    #define CGREEN ""
    #define CYELLOW ""
    #define CBLUE ""
    #define CMAGENTA ""
    #define CCYAN ""
    #define CWHITE ""
#else
    #define CDEFAULT    "\x1B[0m"
    #define CRED        "\x1B[31m"
    #define CGREEN      "\x1B[32m"
    #define CYELLOW     "\x1B[33m"
    #define CBLUE       "\x1B[34m"
    #define CMAGENTA    "\x1B[35m"
    #define CCYAN       "\x1B[36m"
    #define CWHITE      "\x1B[37m"
#endif

#define err(format, ...) printf(CRED "Error" CDEFAULT ": " format, ##__VA_ARGS__)

#define mask(x, y) (x & y)
#define masks(x, y, z) ((x >> z) & (y))

#define sign_extend(v, sb) ((v) | (((v) & (1ll << (sb - 1ll))) ? ~((1ll << (sb - 1ll)) - 1ll) : 0ll))

struct cpu {
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
};

struct cpu_pair {
    struct cpu cpu;
    char *cpu_name;
};

typedef struct {
    char name[16];
    uint64_t offset;
    uint64_t size;
    uint64_t vmaddr;
    uint64_t vmsize;
} segment_t;

typedef struct {
    char name[16];
    uint32_t offset;
    uint64_t size;
    uint32_t index;
} section_t;

typedef struct {
    char *name;
    uint64_t offset;
    uint32_t segment;
    uint32_t library;
} stub_t;

typedef struct {
    char name[256];
    uint64_t offset;
    uint32_t section;
} symbol_t;

typedef struct {
    char *name;
    uint64_t offset;
} function_t;

typedef struct {
    symbol_t *symbols;
    uint32_t nsyms;
    struct dysymtab_command *dysym;
    struct symtab_command *sym;
} symbol_data_t;

int32_t swap_int32_t(int32_t value);
int64_t swap_int64_t(int64_t value);

void *read_bytes(FILE *file, int offset, int size);
uint32_t read_uint32_t(FILE *file, int offset);
uint64_t read_uint64_t(FILE *file, int offset);
uint64_t read_uleb128(uint8_t *data, uint64_t *end);

void str_replace(char *target, const char *needle, const char *replacement);
void read_string(FILE *file, int offset, char *buffer, int buffer_size);
char *read_string_v(FILE *file, int offset, char *terminator);
char *read_string_vm(char *start, int *index, char *terminator);
char *path_combine(char *first, char *second);

char *name_for_cpu(struct cpu *cpu);
struct cpu *cpu_for_name(char *cpu_name);

uint64_t address_for_symbol(symbol_data_t *data, char *name);
char *symbol_for_address(symbol_data_t *data, uint64_t address);

const char *load_command_string(uint32_t cmd);
section_t *section_by_region(section_t *sections, uint64_t address);
section_t *section_by_name(section_t *sections, const char *name);
uint64_t correct_offset(uint64_t offset, segment_t *segments);

#endif