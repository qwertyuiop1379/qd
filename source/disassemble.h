#ifndef disassemble_h
#define disassemble_h

#include "utils.h"

typedef struct {
    uint32_t instruction;
    uint8_t integer_style;
    uint8_t float_style;
    uint8_t group;
    uint64_t pc;
    char *decode_string;
    symbol_data_t *symbol_data;
} decode_context_t;

bool disassemble_master(decode_context_t *context);
void disassemble_reserved(decode_context_t *context);
void disassemble_sve(decode_context_t *context);
void disassemble_data_immediate(decode_context_t *context);
void disassemble_system(decode_context_t *context);
void disassemble_loads_stores(decode_context_t *context);
void disassemble_data_register(decode_context_t *context);
void disassemble_data_float(decode_context_t *context);

#endif