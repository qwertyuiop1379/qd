#include "objc.h"

char *type_for_encode(char *encoded, int *index)
{
	char *ret = NULL;
	char C = encoded[*index];

	switch (C)
	{
		case 'c':
		{
			ret = malloc(5);
			strcpy(ret, "char");

			(*index)++;
			break;
		}

		case 'i':
		{
			ret = malloc(4);
			strcpy(ret, "int");

			(*index)++;
			break;
		}

		case 's':
		{
			ret = malloc(6);
			strcpy(ret, "short");

			(*index)++;
			break;
		}

		case 'l':
		{
			ret = malloc(5);
			strcpy(ret, "long");

			(*index)++;
			break;
		}

		case 'q':
		{
			ret = malloc(10);
			strcpy(ret, "long long");

			(*index)++;
			break;
		}

		case 'C':
		{
			ret = malloc(14);
			strcpy(ret, "unsigned char");

			(*index)++;
			break;
		}

		case 'I':
		{
			ret = malloc(13);
			strcpy(ret, "unsigned int");

			(*index)++;
			break;
		}

		case 'S':
		{
			ret = malloc(15);
			strcpy(ret, "unsigned short");

			(*index)++;
			break;
		}

		case 'L':
		{
			ret = malloc(14);
			strcpy(ret, "unsigned long");

			(*index)++;
			break;
		}

		case 'Q':
		{
			ret = malloc(19);
			strcpy(ret, "unsigned long long");

			(*index)++;
			break;
		}

		case 'f':
		{
			ret = malloc(6);
			strcpy(ret, "float");

			(*index)++;
			break;
		}

		case 'd':
		{
			ret = malloc(7);
			strcpy(ret, "double");

			(*index)++;
			break;
		}

		case 'B':
		{
			ret = malloc(5);
			strcpy(ret, "BOOL");

			(*index)++;
			break;
		}

		case 'v':
		{
			ret = malloc(5);
			strcpy(ret, "void");

			(*index)++;
			break;
		}

		case '*':
		{
			ret = malloc(7);
			strcpy(ret, "char *");

			(*index)++;
			break;
		}

		case '@':
		{
			ret = malloc(5);
			strcpy(ret, "id");

			(*index)++;
			break;
		}

		case '#':
		{
			ret = malloc(6);
			strcpy(ret, "Class");

			(*index)++;
			break;
		}

		case ':':
		{
			ret = malloc(4);
			strcpy(ret, "SEL");

			(*index)++;
			break;
		}

		case '[':
		{
			(*index)++;
			int c = 0;

			char *_count = malloc(1);
			*_count = '\0';

			while ((c = encoded[*index]) && isdigit(c))
			{
				_count = realloc(_count, strlen(_count) + 2);
				strncat(_count, (char *)&c, 1);
				(*index)++;
			}

			uint32_t count = atoi(_count);
			free(_count);

			char *type = type_for_encode(encoded, index);

			uint32_t size = strlen(type) + strlen(_count) + 5;
			ret = malloc(size);
			snprintf(ret, size, "%s [%d]", type, count);

			(*index)++;
			return ret;
		}

		case '(':
		case '{':
		{
			(*index)++;
			int CC = 0;

			char *s_name = malloc(1);
			*s_name = '\0';

			bool depth = 1;
			bool recording = 1;

			while ((CC = encoded[*index]) && depth)
			{
				if (CC == '=') // ignore struct contents for now
					recording = 0;

				if (CC == '}' || CC == ')')
					depth--;

				if (recording)
				{
					s_name = realloc(s_name, strlen(s_name) + 2);
					strncat(s_name, (char *)&CC, 1);
				}

				(*index)++;
			}

			return s_name;
		}

		case 'b':
		{
			(*index)++;
			break;
		}

		case '^':
		{
			(*index)++;

			char *pointer_type = type_for_encode(encoded, index);

			ret = malloc(strlen(pointer_type) + 3);
			snprintf(ret, strlen(pointer_type) + 3, "%s *", pointer_type);
			free(pointer_type);

			break;
		}

		default:
		{
			(*index)++;
			return type_for_encode(encoded, index);
		}
	}

	return ret;
}

char *get_method_chunk(char *method, int *index, bool *has_arg)
{
	int splitter = 0;
	char *chunk = malloc(1);
	*chunk = '\0';

	int C = 0;

	while ((C = method[*index]))
	{
		(*index)++;
		chunk = realloc(chunk, strlen(chunk) + 2);
		strncat(chunk, (char *)&C, 1);

		if (C == ':')
		{
			*has_arg = 1;
			return chunk;
		}
	}

	*has_arg = 0;
	return chunk;
}

void decode_objc_method(FILE *output, char *method_name, char *encoding, bool is_static)
{
	int index = 0;

	char *return_type = type_for_encode(encoding, &index);

	char *self = type_for_encode(encoding, &index);
	free(self);
	char *_cmd = type_for_encode(encoding, &index);
	free(_cmd);

	int method_index = 0;
	bool has_arg = 0;
	char *chunk = get_method_chunk(method_name, &method_index, &has_arg);

	fprintf(output, "%c(%s)", is_static ? '+' : '-', return_type);
	free(return_type);

	if (!has_arg)
		fprintf(output, "%s", chunk);

	size_t length = strlen(encoding);
	uint32_t arg_count = 1;

	while (has_arg)
	{
		char *argument = type_for_encode(encoding, &index);

		fprintf(output, "%s(%s)arg%d", chunk, argument, arg_count++);
		
		free(chunk);
		free(argument);

		chunk = get_method_chunk(method_name, &method_index, &has_arg);

		if (has_arg)
			fprintf(output, " ");
	}

	free(chunk);
	fprintf(output, ";\n");
}

void print_meth_list(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_static, bool is_64_bit)
{
	struct objc2_meth_list *methods = read_bytes(input, arch_offset + address, sizeof(struct objc2_meth_list));
	uint64_t method_offset = arch_offset + address + sizeof(struct objc2_meth_list);

	for (int i = 0; i < methods->count; i++)
	{
		char *method_name;
		uint64_t types;

		if (is_64_bit)
		{
			struct objc2_meth_64 *method = read_bytes(input, method_offset, sizeof(struct objc2_meth_64));
			method_name = read_string_v(input, arch_offset + method->name, "");
			types = method->types;
			free(method);
		}
		else
		{
			struct objc2_meth_32 *method = read_bytes(input, method_offset, sizeof(struct objc2_meth_32));
			method_name = read_string_v(input, arch_offset + method->name, "");
			types = method->types;
			free(method);
		}

		if (strcmp(method_name, ".cxx_destruct"))
		{
			char *encoding = read_string_v(input, arch_offset + types, "");
			decode_objc_method(output, method_name, encoding, is_static);
			free(encoding);
		}

		free(method_name);

		method_offset += is_64_bit ? sizeof(struct objc2_meth_64) : sizeof(struct objc2_meth_32);
	}

	free(methods);
}

char *print_protocols(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit)
{
	uint8_t width = is_64_bit ? 8 : 4;

	char *protocol_list = 0;

	uint64_t count;
	uint64_t offset;

	if (is_64_bit)
	{
		struct objc2_prot_list_64 *protocols = read_bytes(input, arch_offset + address, sizeof(struct objc2_prot_list_64));

		count = protocols->count;
		offset = arch_offset + address + sizeof(struct objc2_prot_list_64);

		free(protocols);
	}
	else
	{
		struct objc2_prot_list_32 *protocols = read_bytes(input, arch_offset + address, sizeof(struct objc2_prot_list_32));

		count = protocols->count;
		offset = arch_offset + address + sizeof(struct objc2_prot_list_32);

		free(protocols);
	}

	if (count)
	{
		protocol_list = malloc(2);
		strcpy(protocol_list, "<");

		for (int i = 0; i < count; i++)
		{
			uint64_t protocol_name;

			if (is_64_bit)
			{
				struct objc2_prot_64 *protocol = read_bytes(input, arch_offset + read_uint64_t(input, offset), sizeof(struct objc2_prot_64));

				protocol_name = protocol->name;

				free(protocol);
			}
			else
			{
				struct objc2_prot_32 *protocol = read_bytes(input, arch_offset + read_uint64_t(input, offset), sizeof(struct objc2_prot_32));

				protocol_name = protocol->name;

				free(protocol);
			}

			char *name = read_string_v(input, arch_offset + protocol_name, "");
			size_t len = strlen(name);

			// fprintf(output, "#import \"%s.h\"\n", name);

			protocol_list = realloc(protocol_list, strlen(protocol_list) + len + 1);
			strncat(protocol_list, name, len);

			if (i != count - 1)
			{
				protocol_list = realloc(protocol_list, strlen(protocol_list) + 3);
				strncat(protocol_list, ", ", 2);
			}

			free(name);

			offset += width;
		}

		protocol_list = realloc(protocol_list, strlen(protocol_list) + 2);
		strncat(protocol_list, ">", 1);
	}

	return protocol_list;
}

void print_ivars(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit)
{
	fprintf(output, "{\n");

	struct objc2_ivar_list *ivars = read_bytes(input, arch_offset + address, sizeof(struct objc2_ivar_list));
	uint64_t ivar_offset = arch_offset + address + sizeof(struct objc2_ivar_list);

	for (int i = 0; i < ivars->count; i++)
	{
		if (is_64_bit)
		{
			struct objc2_ivar_64 *ivar = read_bytes(input, ivar_offset, sizeof(struct objc2_ivar_64));

			char *name = read_string_v(input, arch_offset + ivar->name, "");
			char *type = read_string_v(input, arch_offset + ivar->type, "");

			int index = 0;
			char *type_decode = type_for_encode(type, &index);

			fprintf(output, "\t%s %s;\n", type_decode, name);

			free(name);
			free(type);
			free(type_decode);
			free(ivar);
		}
		else
		{
			struct objc2_ivar_32 *ivar = read_bytes(input, ivar_offset, sizeof(struct objc2_ivar_32));

			char *name = read_string_v(input, arch_offset + ivar->name, "");
			char *type = read_string_v(input, arch_offset + ivar->type, "");

			int index = 0;
			char *type_decode = type_for_encode(type, &index);

			fprintf(output, "\t%s %s;\n", type_decode, name);

			free(name);
			free(type);
			free(type_decode);
			free(ivar);
		}

		ivar_offset += is_64_bit ? sizeof(struct objc2_ivar_64) : sizeof(struct objc2_ivar_32);
	}

	free(ivars);
	fprintf(output, "}\n");
}

void print_forward_declarations(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit)
{
	char **protocols = malloc(0);
	uint32_t prot_count = 0;

	char **classes = malloc(0);
	uint32_t class_count = 0;

	struct objc2_prop_list *properties = read_bytes(input, arch_offset + address, sizeof(struct objc2_prop_list));

	uint64_t prop_offset = arch_offset + address + sizeof(struct objc2_prop_list);

	for (int i = 0; i < properties->count; i++)
	{
		char *name;
		char *attr;

		if (is_64_bit)
		{
			struct objc2_prop_64 *property = read_bytes(input, prop_offset, sizeof(struct objc2_prop_64));
			name = read_string_v(input, arch_offset + property->name, "");
			attr = read_string_v(input, arch_offset + property->attr, "");
			free(property);
		}
		else
		{
			struct objc2_prop_32 *property = read_bytes(input, prop_offset, sizeof(struct objc2_prop_32));
			name = read_string_v(input, arch_offset + property->name, "");
			attr = read_string_v(input, arch_offset + property->attr, "");
			free(property);
		}

		int index = 0;
		char *type = type_for_encode(attr, &index);

		if (attr[index] == '"')
		{
			index++;

			if (attr[index] == '<')
			{
				char *new_type = read_string_vm(attr, &index, "\"");
				index++;

				uint32_t size = strlen(type) + strlen(new_type) + 3;
				type = realloc(type, size);
				strncat(type, " ", 1);
				strncat(type, new_type, size);
				strncat(type, " ", 1);

				char *protocol = malloc(strlen(new_type) - 1);
				strncpy(protocol, new_type + 1, strlen(new_type) - 2);
				protocol[strlen(new_type) - 2] = '\0';

				bool has_protocol = 0;

				for (int i = 0; i < prot_count; i++)
				{
					if (strcmp(protocol, protocols[i]) == 0)
						has_protocol = 1;
				}

				if (has_protocol)
				{
					free(protocol);
				}
				else
				{
					protocols = realloc(protocols, sizeof(char *) * (prot_count + 1));
					protocols[prot_count++] = protocol;
				}

				free(new_type);
			}
			else
			{
				free(type);

				type = read_string_vm(attr, &index, "\"");
				index++;

				size_t len = strlen(type);

				char *class = malloc(len + 1);
				strncpy(class, type, len + 1);

				bool has_class = 0;

				for (int i = 0; i < class_count; i++)
				{
					if (strcmp(class, classes[i]) == 0)
						has_class = 1;
				}

				if (has_class)
				{
					free(class);
				}
				else
				{
					classes = realloc(classes, sizeof(char *) * (class_count + 1));
					classes[class_count++] = class;
				}

				type = realloc(type, len + 3);
				strncat(type, " *", 2);
			}
		}

		free(attr);
		free(type);
		free(name);

		prop_offset += is_64_bit ? sizeof(struct objc2_prop_64) : sizeof(struct objc2_prop_32);
	}

	if (prot_count)
	{
		fprintf(output, "@protocol ");

		for (int i = 0; i < prot_count; i++)
		{
			if (i && i < prot_count)
				fprintf(output, ", ");

			char *protocol = protocols[i];

			fprintf(output, "%s", protocol);

			free(protocol);
		}

		fprintf(output, ";\n");
	}

	if (class_count)
	{
		fprintf(output, "@class ");

		for (int i = 0; i < class_count; i++)
		{
			if (i && i < class_count)
				fprintf(output, ", ");

			char *class = classes[i];

			fprintf(output, "%s", class);

			free(class);
		}

		fprintf(output, ";\n");
	}

	free(properties);
}

void print_properties(FILE *input, FILE *output, uint64_t arch_offset, uint64_t address, bool is_64_bit)
{
	struct objc2_prop_list *properties = read_bytes(input, arch_offset + address, sizeof(struct objc2_prop_list));

	uint64_t prop_offset = arch_offset + address + sizeof(struct objc2_prop_list);

	for (int i = 0; i < properties->count; i++)
	{
		char *name;
		char *attr;

		if (is_64_bit)
		{
			struct objc2_prop_64 *property = read_bytes(input, prop_offset, sizeof(struct objc2_prop_64));
			name = read_string_v(input, arch_offset + property->name, "");
			attr = read_string_v(input, arch_offset + property->attr, "");
			free(property);
		}
		else
		{
			struct objc2_prop_32 *property = read_bytes(input, prop_offset, sizeof(struct objc2_prop_32));
			name = read_string_v(input, arch_offset + property->name, "");
			attr = read_string_v(input, arch_offset + property->attr, "");
			free(property);
		}

		fprintf(output, "@property (");

		int index = 0;
		char *type = type_for_encode(attr, &index);

		if (attr[index] == '"')
		{
			index++;

			if (attr[index] == '<')
			{
				char *new_type = read_string_vm(attr, &index, "\"");
				index++;

				uint32_t size = strlen(type) + strlen(new_type) + 3;
				type = realloc(type, size);
				strncat(type, " ", 1);
				strncat(type, new_type, size);
				strncat(type, " ", 1);

				free(new_type);
			}
			else
			{
				free(type);

				type = read_string_vm(attr, &index, "\"");
				index++;

				type = realloc(type, strlen(type) + 3);
				strncat(type, " *", 2);
			}
		}
		else
		{
			type = realloc(type, strlen(type) + 2);
			strncat(type, " ", 1);
		}

		uint32_t attributes = 0;
		bool weak = 0;
		bool readonly = 0;
		bool nonatomic = 0;
		bool copy = 0;
		bool retain = 0;
		char *getter = NULL;
		char *setter = NULL;

		while (attr[index] == ',' || attr[index] == '"')
		{
			index++;

			switch (attr[index])
			{
				case 'W':
				{
					attributes++;
					index++;

					weak = 1;
					break;
				}

				case 'R':
				{
					attributes++;
					index++;

					readonly = 1;
					break;
				}

				case 'N':
				{
					attributes++;
					index++;

					nonatomic = 1;
					break;
				}

				case 'C':
				{
					attributes++;
					index++;

					copy = 1;
					break;
				}

				case '&':
				{
					attributes++;
					index++;

					retain = 1;
					break;
				}

				case 'G':
				{
					attributes++;
					index++;

					getter = read_string_vm(attr, &index, ",\"");
					break;
				}

				case 'S':
				{
					attributes++;
					index++;

					setter = read_string_vm(attr, &index, ",\"");
					break;
				}

				default:
				{
					index++;

					continue;
				}
			}
		}

		free(attr);

		if (weak)
		{
			fprintf(output, "weak");
			
			if (--attributes)
				fprintf(output, ", ");
		}

		if (readonly)
		{
			fprintf(output, "readonly");
			
			if (--attributes)
				fprintf(output, ", ");
		}

		if (nonatomic)
		{
			fprintf(output, "nonatomic");
			
			if (--attributes)
				fprintf(output, ", ");
		}

		if (copy)
		{
			fprintf(output, "copy");
			
			if (--attributes)
				fprintf(output, ", ");
		}

		if (retain)
		{
			fprintf(output, "retain");
			
			if (--attributes)
				fprintf(output, ", ");
		}

		if (getter)
		{
			fprintf(output, "getter=%s", getter);
			free(getter);
			
			if (--attributes)
				fprintf(output, ", ");
		}

		if (setter)
		{
			fprintf(output, "setter=%s", setter);
			free(setter);
			
			if (--attributes)
				fprintf(output, ", ");
		}

		fprintf(output, ") %s%s;\n", type, name);

		free(type);
		free(name);

		prop_offset += is_64_bit ? sizeof(struct objc2_prop_64) : sizeof(struct objc2_prop_32);
	}

	free(properties);
}