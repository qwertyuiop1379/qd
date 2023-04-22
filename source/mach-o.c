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

#include <string.h>
#include "mach-o.h"
#include "utils.h"

void swap_super_blob(struct SuperBlob *sb)
{
	sb->type = swap_int32_t(sb->type);
	sb->length = swap_int32_t(sb->length);
	sb->count = swap_int64_t(sb->count);
	
	for (int i = 0; i < sb->count; i++)
		sb->index[i] = swap_int64_t(sb->index[i]);
}

void swap_fat_header(struct fat_header *fat_header, enum ByteOrder target_byte_sex)
{
	fat_header->magic = swap_int32_t(fat_header->magic);
	fat_header->nfat_arch = swap_int32_t(fat_header->nfat_arch);
}

void swap_fat_arch(struct fat_arch *fat_archs, uint32_t nfat_arch, enum ByteOrder target_byte_sex)
{
	for (uint32_t i = 0; i < nfat_arch; i++)
    {
	    fat_archs[i].cputype = swap_int32_t(fat_archs[i].cputype);
	    fat_archs[i].cpusubtype = swap_int32_t(fat_archs[i].cpusubtype);
	    fat_archs[i].offset = swap_int32_t(fat_archs[i].offset);
	    fat_archs[i].size = swap_int32_t(fat_archs[i].size);
	    fat_archs[i].align = swap_int32_t(fat_archs[i].align);
	}
}

void swap_mach_header(struct mach_header *mh, enum ByteOrder target_byte_sex)
{
	mh->magic = swap_int32_t(mh->magic);
	mh->cputype = swap_int32_t(mh->cputype);
	mh->cpusubtype = swap_int32_t(mh->cpusubtype);
	mh->filetype = swap_int32_t(mh->filetype);
	mh->ncmds = swap_int32_t(mh->ncmds);
	mh->sizeofcmds = swap_int32_t(mh->sizeofcmds);
	mh->flags = swap_int32_t(mh->flags);
}

void swap_mach_header_64(struct mach_header_64 *mh, enum ByteOrder target_byte_sex)
{
	mh->magic = swap_int32_t(mh->magic);
	mh->cputype = swap_int32_t(mh->cputype);
	mh->cpusubtype = swap_int32_t(mh->cpusubtype);
	mh->filetype = swap_int32_t(mh->filetype);
	mh->ncmds = swap_int32_t(mh->ncmds);
	mh->sizeofcmds = swap_int32_t(mh->sizeofcmds);
	mh->flags = swap_int32_t(mh->flags);
	mh->reserved = swap_int32_t(mh->reserved);
}

void swap_load_command(struct load_command *lc, enum ByteOrder target_byte_sex)
{
	lc->cmd = swap_int32_t(lc->cmd);
	lc->cmdsize = swap_int32_t(lc->cmdsize);
}

void swap_segment_command(struct segment_command *sg, enum ByteOrder target_byte_sex)
{
	sg->cmd = swap_int32_t(sg->cmd);
	sg->cmdsize = swap_int32_t(sg->cmdsize);
	sg->vmaddr = swap_int32_t(sg->vmaddr);
	sg->vmsize = swap_int32_t(sg->vmsize);
	sg->fileoff = swap_int32_t(sg->fileoff);
	sg->filesize = swap_int32_t(sg->filesize);
	sg->maxprot = swap_int32_t(sg->maxprot);
	sg->initprot = swap_int32_t(sg->initprot);
	sg->nsects = swap_int32_t(sg->nsects);
	sg->flags = swap_int32_t(sg->flags);
}

void swap_segment_command_64(struct segment_command_64* sg, enum ByteOrder target_byte_sex)
{
	sg->cmd = swap_int32_t(sg->cmd);
	sg->cmdsize = swap_int32_t(sg->cmdsize);
	sg->vmaddr = swap_int64_t(sg->vmaddr);
	sg->vmsize = swap_int64_t(sg->vmsize);
	sg->fileoff = swap_int64_t(sg->fileoff);
	sg->filesize = swap_int64_t(sg->filesize);
	sg->maxprot = swap_int32_t(sg->maxprot);
	sg->initprot = swap_int32_t(sg->initprot);
	sg->nsects = swap_int32_t(sg->nsects);
	sg->flags = swap_int32_t(sg->flags);
}

void swap_symtab_command(struct symtab_command *st, enum ByteOrder target_byte_sex)
{
	st->cmd = swap_int32_t(st->cmd);
	st->cmdsize = swap_int32_t(st->cmdsize);
	st->symoff = swap_int32_t(st->symoff);
	st->nsyms = swap_int32_t(st->nsyms);
	st->stroff = swap_int32_t(st->stroff);
	st->strsize = swap_int32_t(st->strsize);
}

// const struct section *sect_by_name(struct mach_header *header, const char *segname, const char *sectname)
// {
// 	struct segment_command *segment;
// 	struct section *section;
        
// 	segment = (char *)header + sizeof(struct mach_header);

// 	for (uint32_t i = 0; i < header->ncmds; i++)
// 	{
// 	    if (segment->cmd == LC_SEGMENT)
// 		{
// 			if (strncmp(segment->segname, segname, sizeof(segment->segname)) == 0 || header->filetype == MH_OBJECT)
// 			{
// 				section = (char *)segment + sizeof(struct segment_command);
// 				for (uint32_t j = 0; j < segment->nsects; j++)
// 				{
// 					if(strncmp(section->sectname, sectname, sizeof(section->sectname)) == 0 && strncmp(section->segname, segname, sizeof(section->segname)) == 0)
// 						return section;

// 					section = (char *)section + sizeof(struct section);
// 				}
// 			}
// 		}

// 	    segment = (char *)segment + segment->cmdsize;
// 	}

// 	return NULL;
// }

// const struct section_64 *sect_by_name_64(struct mach_header_64 *header, const char *segname, const char *sectname)
// {
// 	struct segment_command_64 *segment;
// 	struct section_64 *section;
        
// 	segment = (char *)header + sizeof(struct mach_header_64);

// 	for (uint32_t i = 0; i < header->ncmds; i++)
// 	{
// 	    if (segment->cmd == LC_SEGMENT_64)
// 		{
// 			if (strncmp(segment->segname, segname, sizeof(segment->segname)) == 0 || header->filetype == MH_OBJECT)
// 			{
// 				section = (char *)segment + sizeof(struct segment_command_64);
// 				for (uint32_t j = 0; j < segment->nsects; j++)
// 				{
// 					if(strncmp(section->sectname, sectname, sizeof(section->sectname)) == 0 && strncmp(section->segname, segname, sizeof(section->segname)) == 0)
// 						return section;

// 					section = (char *)section + sizeof(struct section_64);
// 				}
// 			}
// 		}

// 	    segment = (char *)segment + segment->cmdsize;
// 	}

// 	return NULL;
// }