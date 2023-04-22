#ifndef objc_h
#define objc_h

char *type_for_encode(char *encoded, int *index);
void decode_objc_method(FILE *output, char *method_name, char *encoding, bool is_static);

void print_meth_list(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_static, bool is_64_bit);
char *print_protocols(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit);
void print_ivars(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit);
void print_properties(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit);
void print_forward_declarations(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit);

#endif