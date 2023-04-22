#include <cxxabi.h>

extern "C" char *demangle_symbol(char *in)
{
	int status = -1;
	char *demangled_name = abi::__cxa_demangle(in + 1, NULL, NULL, &status);
	return demangled_name;
}