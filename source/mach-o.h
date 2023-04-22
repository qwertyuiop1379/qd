/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef mach_o_h
#define mach_o_h

#include <stdint.h>

typedef int cpu_type_t;
typedef int cpu_subtype_t;
typedef int vm_prot_t;

#define CPU_ARCH_MASK 0xff000000
#define CPU_ARCH_ABI64 0x01000000
#define CPU_ARCH_ABI64_32 0x02000000

#define CPU_TYPE_X86 ((cpu_type_t) 7)
#define CPU_TYPE_X86_64 (CPU_TYPE_X86 | CPU_ARCH_ABI64)

#define CPU_TYPE_ARM ((cpu_type_t) 12)
#define CPU_TYPE_ARM64 (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM64_32 (CPU_TYPE_ARM | CPU_ARCH_ABI64_32)

#define CPU_SUBTYPE_MULTIPLE ((cpu_subtype_t) -1)

#define CPU_SUBTYPE_ARM_ALL ((cpu_subtype_t) 0)
#define CPU_SUBTYPE_ARM_V6 ((cpu_subtype_t) 6)
#define CPU_SUBTYPE_ARM_V7 ((cpu_subtype_t) 9)
#define CPU_SUBTYPE_ARM_V7S ((cpu_subtype_t) 11)

#define CPU_SUBTYPE_ARM64_ALL ((cpu_subtype_t) 0)
#define CPU_SUBTYPE_ARM64E ((cpu_subtype_t) 2)

#define CPU_SUBTYPE_ARM64_32_ALL ((cpu_subtype_t) 0)

#define MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe
#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe

#define	MH_OBJECT 0x1

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca
#define FAT_MAGIC_64 0xcafebabf
#define FAT_CIGAM_64 0xbfbafeca

#define LC_REQ_DYLD 0x80000000

#define	LC_SEGMENT 0x1
#define	LC_SYMTAB 0x2
#define	LC_DYSYMTAB 0xb
#define	LC_LOAD_DYLIB 0xc
#define	LC_ID_DYLIB 0xd
#define	LC_LOAD_WEAK_DYLIB (0x18 | LC_REQ_DYLD)
#define	LC_SEGMENT_64 0x19
#define LC_CODE_SIGNATURE 0x1d
#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD)
#define LC_DYLD_INFO 0x22
#define LC_DYLD_INFO_ONLY (0x22 | LC_REQ_DYLD)
#define LC_FUNCTION_STARTS 0x26
#define LC_DATA_IN_CODE 0x29

#define N_STAB 0xe0
#define N_PEXT 0x10
#define N_TYPE 0xe
#define N_EXT 0x1
#define N_UNDF 0x0
#define N_ABS 0x2
#define N_SECT 0xe
#define N_PBUD 0xc
#define N_INDR 0xa

#define S_NON_LAZY_SYMBOL_POINTERS 0x6
#define S_LAZY_SYMBOL_POINTERS 0x7
#define S_SYMBOL_STUBS 0x8
#define S_MOD_INIT_FUNC_POINTERS 0x9

#define BIND_OPCODE_DONE 0
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM 1
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB 2
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM 3
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 4
#define BIND_OPCODE_SET_TYPE_IMM 5
#define BIND_OPCODE_SET_ADDEND_SLEB 6
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 7
#define BIND_OPCODE_ADD_ADDR_ULEB 8
#define BIND_OPCODE_DO_BIND 9
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB 10
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED 11
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 12
#define BIND_OPCODE_THREADED 13

#define	BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB 0
#define	BIND_SUBOPCODE_THREADED_APPLY 1

enum ByteOrder {
	BigEndian,
	LittleEndian,
	Unknown
};

struct SuperBlob {
    uint32_t type;
	uint32_t length;
    uint32_t count;
    uint64_t index[];
};

struct mach_header {
	uint32_t magic;
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
};

struct mach_header_64 {
	uint32_t magic;
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
	uint32_t reserved;
};

struct fat_header {
	uint32_t magic;
	uint32_t nfat_arch;
};

struct fat_arch {
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	uint32_t offset;
	uint32_t size;
	uint32_t align;
};

union lc_str {
	uint32_t offset;
	#ifndef __LP64__
	char *ptr;
	#endif 
};

struct load_command {
	uint32_t cmd;
	uint32_t cmdsize;
};

struct segment_command {
	uint32_t cmd;
	uint32_t cmdsize;
	char segname[16];
	uint32_t vmaddr;
	uint32_t vmsize;
	uint32_t fileoff;
	uint32_t filesize;
	vm_prot_t maxprot;
	vm_prot_t initprot;
	uint32_t nsects;
	uint32_t flags;
};

struct segment_command_64 {
	uint32_t cmd;
	uint32_t cmdsize;
	char segname[16];
	uint64_t vmaddr;
	uint64_t vmsize;
	uint64_t fileoff;
	uint64_t filesize;
	vm_prot_t maxprot;
	vm_prot_t initprot;
	uint32_t nsects;
	uint32_t flags;
};

struct section {
	char sectname[16];
	char segname[16];
	uint32_t addr;
	uint32_t size;
	uint32_t offset;
	uint32_t align;
	uint32_t reloff;
	uint32_t nreloc;
	uint32_t flags;
	uint32_t reserved1;
	uint32_t reserved2;
};

struct section_64 {
	char sectname[16];
	char segname[16];
	uint64_t addr;
	uint64_t size;
	uint32_t offset;
	uint32_t align;
	uint32_t reloff;
	uint32_t nreloc;
	uint32_t flags;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
};

struct dylib {
	union lc_str  name;
	uint32_t timestamp;
	uint32_t current_version;
	uint32_t compatibility_version;
};

struct dylib_command {
	uint32_t cmd;
	uint32_t cmdsize;
	struct dylib dylib;
};

struct symtab_command {
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t symoff;
	uint32_t nsyms;
	uint32_t stroff;
	uint32_t strsize;
};

struct dysymtab_command
{
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t ilocalsym;
	uint32_t nlocalsym;
	uint32_t iextdefsym;
	uint32_t nextdefsym;
	uint32_t iundefsym;
	uint32_t nundefsym;
	uint32_t modtaboff;
	uint32_t nmodtab;
	uint32_t extrefsymoff;
	uint32_t nextrefsyms;
	uint32_t indirectsymoff;
	uint32_t nindirectsyms;
	uint32_t extreloff;
	uint32_t nextrel;
	uint32_t locreloff;
	uint32_t nlocrel;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct nlist {
	union {
		#ifndef __LP64__
		char *n_name;
		#endif
		uint32_t n_strx;
	} n_un;
	uint8_t n_type;
	uint8_t n_sect;
	int16_t n_desc;
	uint32_t n_value;
};

struct nlist_64 {
    union {
        uint32_t  n_strx;
    } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

struct dyld_info_command {
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t rebase_off;
	uint32_t rebase_size;
	uint32_t bind_off;
	uint32_t bind_size;
	uint32_t weak_bind_off;
	uint32_t weak_bind_size;
	uint32_t lazy_bind_off;
	uint32_t lazy_bind_size;
	uint32_t export_off;
	uint32_t export_size;
};

struct objc2_category_32 {
	uint32_t name;
	uint32_t _class;
	uint32_t inst_methods;
	uint32_t class_methods;
	uint32_t prots;
	uint32_t props;
};

struct objc2_category_64 {
	uint64_t name;
	uint64_t _class;
	uint64_t inst_methods;
	uint64_t class_methods;
	uint64_t prots;
	uint64_t props;
};

struct objc2_class_32 {
	uint32_t isa;
	uint32_t superclass;
	uint32_t cache;
	uint32_t vtable;
	uint32_t info;
};

struct objc2_class_64 {
	uint64_t isa;
	uint64_t superclass;
	uint64_t cache;
	uint64_t vtable;
	uint64_t info;
};

struct objc2_class_ro_32 {
	uint32_t flags;
	uint32_t ivar_base_start;
	uint32_t ivar_base_size;
	uint32_t ivar_lyt;
	uint32_t name;
	uint32_t base_meths;
	uint32_t base_prots;
	uint32_t ivars;
	uint32_t weak_ivar_lyt;
	uint32_t base_props;
};

struct objc2_class_ro_64 {
	uint32_t flags;
	uint32_t ivar_base_start;
	uint32_t ivar_base_size;
	uint32_t reserved;
	uint64_t ivar_lyt;
	uint64_t name;
	uint64_t base_meths;
	uint64_t base_prots;
	uint64_t ivars;
	uint64_t weak_ivar_lyt;
	uint64_t base_props;
};

struct objc2_prot_list_32 {
	uint32_t count;
};

struct objc2_prot_list_64 {
	uint64_t count;
};

struct objc2_prot_32 {
	uint32_t isa;
	uint32_t name;
	uint32_t protocols;
	uint32_t inst_meths;
	uint32_t class_meths;
	uint32_t opt_inst_meths;
	uint32_t opt_class_meths;
	uint32_t inst_props;
	uint32_t cb;
	uint32_t flags;
};

struct objc2_prot_64 {
	uint64_t isa;
	uint64_t name;
	uint64_t protocols;
	uint64_t inst_meths;
	uint64_t class_meths;
	uint64_t opt_inst_meths;
	uint64_t opt_class_meths;
	uint64_t inst_props;
	uint32_t cb;
	uint32_t flags;
};

struct objc2_prop_list {
	uint32_t entrysize;
	uint32_t count;
};

struct objc2_prop_32 {
	uint32_t name;
	uint32_t attr;
};

struct objc2_prop_64 {
	uint64_t name;
	uint64_t attr;
};

struct objc2_ivar_list {
	uint32_t entrysize;
	uint32_t count;
};

struct objc2_ivar_32 {
	uint32_t offset;
	uint32_t name;
	uint32_t type;
	uint32_t align;
	uint32_t size;
};

struct objc2_ivar_64 {
	uint64_t offset;
	uint64_t name;
	uint64_t type;
	uint32_t align;
	uint32_t size;
};

struct objc2_meth_list {
	uint32_t entrysize;
	uint32_t count;
};

struct objc2_meth_32 {
	uint32_t name;
	uint32_t types;
	uint32_t imp; 
};

struct objc2_meth_64 {
	uint64_t name;
	uint64_t types;
	uint64_t imp; 
};

extern void swap_super_blob(struct SuperBlob *sb);
extern void swap_fat_header(struct fat_header *fat_header, enum ByteOrder target_byte_order);
extern void swap_fat_arch(struct fat_arch *fat_archs, uint32_t nfat_arch, enum ByteOrder target_byte_order);
extern void swap_mach_header(struct mach_header *mh, enum ByteOrder target_byte_order);
extern void swap_mach_header_64(struct mach_header_64 *mh, enum ByteOrder target_byte_order);
extern void swap_load_command(struct load_command *lc, enum ByteOrder target_byte_order);
extern void swap_segment_command(struct segment_command *sg,enum ByteOrder target_byte_order);
extern void swap_segment_command_64(struct segment_command_64 *sg, enum ByteOrder target_byte_order);
extern void swap_symtab_command(struct symtab_command *st, enum ByteOrder target_byte_sex);

const struct section *sect_by_name(struct mach_header *header, const char *segname, const char *sectname);
const struct section_64 *sect_by_name_64(struct mach_header_64 *header, const char *segname, const char *sectname);

#endif