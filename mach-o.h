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

#ifdef __linux__
    #define uint64_t unsigned long long
#endif

typedef int cpu_type_t;
typedef int cpu_subtype_t;

typedef int vm_prot_t;

#define CPU_ARCH_MASK 0xff000000
#define CPU_ARCH_ABI64 0x01000000
#define CPU_ARCH_ABI64_32 0x02000000

#define CPU_TYPE_X86 ((cpu_type_t) 7)
#define CPU_TYPE_I386 CPU_TYPE_X86
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

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca
#define FAT_MAGIC_64 0xcafebabf
#define FAT_CIGAM_64 0xbfbafeca

#define	LC_SEGMENT 0x1
#define	LC_SYMTAB 0x2
#define	LC_DYSYMTAB 0xb
#define	LC_LOAD_DYLIB 0xc
#define	LC_ID_DYLIB 0xd
#define	LC_SEGMENT_64 0x19
#define LC_CODE_SIGNATURE 0x1d
#define LC_FUNCTION_STARTS 0x26

struct linkedit_section {
    uint32_t magic;
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
	char  sectname[16];
	char  segname[16];
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
	char  sectname[16];
	char  segname[16];
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

enum ByteOrder : unsigned int {
	BigEndian,
	LittleEndian,
	Unknown
};

extern void swap_fat_header(struct fat_header *fat_header, enum ByteOrder target_byte_order);
extern void swap_fat_arch(struct fat_arch *fat_archs, uint32_t nfat_arch, enum ByteOrder target_byte_order);
extern void swap_mach_header(struct mach_header *mh, enum ByteOrder target_byte_order);
extern void swap_mach_header_64(struct mach_header_64 *mh, enum ByteOrder target_byte_order);
extern void swap_load_command(struct load_command *lc, enum ByteOrder target_byte_order);
extern void swap_segment_command(struct segment_command *sg,enum ByteOrder target_byte_order);
extern void swap_segment_command_64(struct segment_command_64 *sg, enum ByteOrder target_byte_order);

#endif