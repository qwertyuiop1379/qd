#ifndef demangle_h
#define demangle_h

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC extern
#endif

EXTERNC char *demangle_symbol(char *in);

#undef EXTERNC

#endif