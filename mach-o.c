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

#include "mach-o.h"
#include "utils.h"

void swap_fat_header(struct fat_header *fat_header, enum ByteOrder target_byte_sex)
{
	fat_header->magic = swap_int32(fat_header->magic);
	fat_header->nfat_arch = swap_int32(fat_header->nfat_arch);
}

void swap_fat_arch(struct fat_arch *fat_archs, uint32_t nfat_arch, enum ByteOrder target_byte_sex)
{
    uint32_t i;

	for (i = 0; i < nfat_arch; i++)
    {
	    fat_archs[i].cputype = swap_int32(fat_archs[i].cputype);
	    fat_archs[i].cpusubtype = swap_int32(fat_archs[i].cpusubtype);
	    fat_archs[i].offset = swap_int32(fat_archs[i].offset);
	    fat_archs[i].size = swap_int32(fat_archs[i].size);
	    fat_archs[i].align = swap_int32(fat_archs[i].align);
	}
}

void swap_mach_header(struct mach_header *mh, enum ByteOrder target_byte_sex)
{
	mh->magic = swap_int32(mh->magic);
	mh->cputype = swap_int32(mh->cputype);
	mh->cpusubtype = swap_int32(mh->cpusubtype);
	mh->filetype = swap_int32(mh->filetype);
	mh->ncmds = swap_int32(mh->ncmds);
	mh->sizeofcmds = swap_int32(mh->sizeofcmds);
	mh->flags = swap_int32(mh->flags);
}

void swap_mach_header_64(struct mach_header_64 *mh, enum ByteOrder target_byte_sex)
{
	mh->magic = swap_int32(mh->magic);
	mh->cputype = swap_int32(mh->cputype);
	mh->cpusubtype = swap_int32(mh->cpusubtype);
	mh->filetype = swap_int32(mh->filetype);
	mh->ncmds = swap_int32(mh->ncmds);
	mh->sizeofcmds = swap_int32(mh->sizeofcmds);
	mh->flags = swap_int32(mh->flags);
	mh->reserved = swap_int32(mh->reserved);
}

void swap_load_command(struct load_command *lc, enum ByteOrder target_byte_sex)
{
	lc->cmd = swap_int32(lc->cmd);
	lc->cmdsize = swap_int32(lc->cmdsize);
}

void swap_segment_command(struct segment_command *sg, enum ByteOrder target_byte_sex)
{
	sg->cmd = swap_int32(sg->cmd);
	sg->cmdsize = swap_int32(sg->cmdsize);
	sg->vmaddr = swap_int32(sg->vmaddr);
	sg->vmsize = swap_int32(sg->vmsize);
	sg->fileoff = swap_int32(sg->fileoff);
	sg->filesize = swap_int32(sg->filesize);
	sg->maxprot = swap_int32(sg->maxprot);
	sg->initprot = swap_int32(sg->initprot);
	sg->nsects = swap_int32(sg->nsects);
	sg->flags = swap_int32(sg->flags);
}

void swap_segment_command_64(struct segment_command_64* sg, enum ByteOrder target_byte_sex)
{
	sg->cmd = swap_int32(sg->cmd);
	sg->cmdsize = swap_int32(sg->cmdsize);
	sg->vmaddr = swap_int64_t(sg->vmaddr);
	sg->vmsize = swap_int64_t(sg->vmsize);
	sg->fileoff = swap_int64_t(sg->fileoff);
	sg->filesize = swap_int64_t(sg->filesize);
	sg->maxprot = swap_int32(sg->maxprot);
	sg->initprot = swap_int32(sg->initprot);
	sg->nsects = swap_int32(sg->nsects);
	sg->flags = swap_int32(sg->flags);
}