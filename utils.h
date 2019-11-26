#include <stdio.h>
#include "mach-o.h"

#define mask(x, y) (x & y)
#define masks(x, y, z) ((x >> z) & (y))

#define CDEFAULT    "\x1B[0m"
#define CRED        "\x1B[31m"
#define CGREEN      "\x1B[32m"
#define CYELLOW     "\x1B[33m"
#define CBLUE       "\x1B[34m"
#define CMAGENTA    "\x1B[35m"
#define CCYAN       "\x1B[36m"
#define CWHITE      "\x1B[37m"

#define err(format, ...) printf(CRED "Error" CDEFAULT ": " format, ##__VA_ARGS__)

struct cpu {
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
};

struct cpu_pair {
    struct cpu cpu;
    char *cpu_name;
};

void disassemble(uint32_t instr, char *asm_output);
void *read_bytes(FILE *file, int offset, int size);
uint32_t read_uint32_t(FILE *file, int offset);
void read_string(FILE *file, int offset, char *buffer, int buffer_size);
void str_replace(char *target, const char *needle, const char *replacement);
int swap_int32(int value);
uint32_t swap_uint32_t(uint32_t value);
char *name_for_cpu(struct cpu *cpu);
struct cpu *cpu_for_name(char *cpu_name);