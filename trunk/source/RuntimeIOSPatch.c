// Copyright 2010 Joseph Jordan <joe.ftpii@psychlaw.com.au>
// This code is licensed to you under the terms of the GNU GPL, version 2;
// see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

// Wii U vWii patches Copyright 2012/2013 damysteryman

#include <gccore.h>
#include <ogc/machine/processor.h>
#include <string.h>

#include "RuntimeIOSPatch.h"

#define MEM_REG_BASE 0xd8b4000
#define MEM_PROT (MEM_REG_BASE + 0x20a)

static void disable_memory_protection()
{
	write32(MEM_PROT, read32(MEM_PROT) & 0x0000FFFF);
}

static u32 apply_patch(char *name, const u8 *pattern, u32 pattern_size, const u8 *patch, u32 patch_size, u32 patch_offset)
{
	u8 *ptr_start = (u8*)*((u32*)0x80003134), *ptr_end = (u8*)0x94000000;
	u32 found = 0;
	u8 *location = NULL;
	while (ptr_start < (ptr_end - patch_size))
	{
		if (!memcmp(ptr_start, pattern, pattern_size))
		{
			found++;
			location = ptr_start + patch_offset;
			u8 *start = location;
			u32 i;
			for (i = 0; i < patch_size; i++)
			{
				*location++ = patch[i];
			}
			DCFlushRange((u8 *)(((u32)start) >> 5 << 5), (patch_size >> 5 << 5) + 64);
			ICInvalidateRange((u8 *)(((u32)start) >> 5 << 5), (patch_size >> 5 << 5) + 64);
		}
		ptr_start++;
	}
	return found;
}

/*** Commonly used patches ***/
static const u8 di_readlimit_old[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x0A, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x7E, 0xD4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08
};

static const u8 di_readlimit_patch[] = { 0x7e, 0xd4 };

const u8 isfs_permissions_old[] = { 0x42, 0x8B, 0xD0, 0x01, 0x25, 0x66 };
const u8 isfs_permissions_patch[] = { 0x42, 0x8B, 0xE0, 0x01, 0x25, 0x66 };
static const u8 setuid_old[] = { 0xD1, 0x2A, 0x1C, 0x39 };
static const u8 setuid_patch[] = { 0x46, 0xC0 };
const u8 es_identify_old[] = { 0x28, 0x03, 0xD1, 0x23 };
const u8 es_identify_patch[] = { 0x00, 0x00 };
const u8 hash_old[] = { 0x20, 0x07, 0x23, 0xA2 };
const u8 hash_patch[] = { 0x00 };
const u8 new_hash_old[] = { 0x20, 0x07, 0x4B, 0x0B };
const u8 version_check[] = { 0xD2, 0x01, 0x4E, 0x56 };
const u8 version_patch[] = { 0xE0, 0x01, 0x4E, 0x56 };

/*** Following patches added by damysteryman, taken from sciifii v5 ***/
/*const u8 MEM2_prot_old[] = { 0xB5, 0x00, 0x4B, 0x09, 0x22, 0x01, 0x80, 0x1A, 0x22, 0xF0 };
const u8 MEM2_prot_patch[] = { 0xB5, 0x00, 0x4B, 0x09, 0x22, 0x00, 0x80, 0x1A, 0x22, 0xF0 };
const u8 ES_OpenTitleContent1_old[] = { 0x9D, 0x05, 0x42, 0x9D, 0xD0, 0x03 };
const u8 ES_OpenTitleContent1_patch[] = { 0x9D, 0x05, 0x42, 0x9D, 0xE0, 0x03 };
const u8 ES_OpenTitleContent2_old[] = { 0xD4, 0x01, 0x4C, 0x36, 0xE0, 0x3B };
const u8 ES_OpenTitleContent2_patch[] = { 0xE0, 0x01, 0x4C, 0x36, 0xE0, 0x3B };
const u8 ES_ReadContent_old[] = {
	0xFC, 0x0F, 0xB5, 0x30, 0x1C, 0x14, 0x1C, 0x1D, 0x4B, 0x0E, 0x68, 0x9B,
	0x2B, 0x00, 0xD0, 0x03, 0x29, 0x00, 0xDB, 0x01, 0x29, 0x0F, 0xDD, 0x01 };
const u8 ES_ReadContent_patch[] = {
	0xFC, 0x0F, 0xB5, 0x30, 0x1C, 0x14, 0x1C, 0x1D, 0x4B, 0x0E, 0x68, 0x9B,
	0x2B, 0x00, 0x46, 0xC0, 0x29, 0x00, 0x46, 0xC0, 0x29, 0x0F, 0xE0, 0x01 };
const u8 ES_CloseContent_old[] = {
	0xB5, 0x10, 0x4B, 0x10, 0x68, 0x9B, 0x2B, 0x00, 0xD0, 0x03, 0x29, 0x00,
	0xDB, 0x01, 0x29, 0x0F, 0xDD, 0x01 };
const u8 ES_CloseContent_patch[] = {
	0xB5, 0x10, 0x4B, 0x10, 0x68, 0x9B, 0x2B, 0x00, 0x46, 0xC0, 0x29, 0x00,
	0x46, 0xC0, 0x29, 0x0F, 0xE0, 0x01 };
const u8 ES_TitleDeleteCheck_old[] = { 0xD8, 0x00, 0x4A, 0x04 };
const u8 ES_TitleDeleteCheck_patch[] = { 0xE0, 0x00, 0x4A, 0x04 };*/

/** Following patches made my damysteryman for use with Wii U's vWii **/
const u8 Kill_AntiSysTitleInstallv3_pt1_old[] = { 0x68, 0x1A, 0x2A, 0x01, 0xD0, 0x05 };	// Make sure that the pt1
const u8 Kill_AntiSysTitleInstallv3_pt1_patch[] = { 0x68, 0x1A, 0x2A, 0x01, 0x46, 0xC0 };	// patch is applied twice. -dmm
const u8 Kill_AntiSysTitleInstallv3_pt2_old[] = { 0xD0, 0x02, 0x33, 0x06, 0x42, 0x9A, 0xD1, 0x01 };	// Make sure that the pt2 patch
const u8 Kill_AntiSysTitleInstallv3_pt2_patch[] = { 0x46, 0xC0, 0x33, 0x06, 0x42, 0x9A, 0xE0, 0x01 };	// is also applied twice. -dmm
const u8 Kill_AntiSysTitleInstallv3_pt3_old[] = { 0x68, 0xFB, 0x2B, 0x00, 0xDB, 0x01 };
const u8 Kill_AntiSysTitleInstallv3_pt3_patch[] = { 0x68, 0xFB, 0x2B, 0x00, 0xDB, 0x10 };

/*** SetAHBPROT patch by davebaol. Use it only if you want to keep full hardware access rights after an IOS reload ***/
/*const u8 es_set_ahbprot_old[] = { 0x68, 0x5B, 0x22, 0xEC, 0x00, 0x52, 0x18, 0x9B, 0x68, 0x1B, 0x46, 0x98, 0x07, 0xDB };
const u8 es_set_ahbprot_patch[]   = { 0x01 };

u32 IOSPATCH_AHBPROT()
{
	if (AHBPROT_DISABLED)
	{
		write32(MEM_PROT, read32(MEM_PROT) & 0x0000FFFF);
		//return apply_patch("set_ahbprot", check_tmd_old, sizeof(check_tmd_old), check_tmd_patch, sizeof(check_tmd_patch), 6);
		return apply_patch("es_set_ahbprot", es_set_ahbprot_old, sizeof(es_set_ahbprot_old), es_set_ahbprot_patch, sizeof(es_set_ahbprot_patch), 25);
	}
	return 0;
}*/

u32 IOSPATCH_Apply()
{
	u32 count = 0;
	if (AHBPROT_DISABLED)
	{
		disable_memory_protection();
		count += apply_patch("di_readlimit", di_readlimit_old, sizeof(di_readlimit_old), di_readlimit_patch, sizeof(di_readlimit_patch), 12);
		count += apply_patch("isfs_permissions", isfs_permissions_old, sizeof(isfs_permissions_old), isfs_permissions_patch, sizeof(isfs_permissions_patch), 0);
		count += apply_patch("es_setuid", setuid_old, sizeof(setuid_old), setuid_patch, sizeof(setuid_patch), 0);
		count += apply_patch("es_identify", es_identify_old, sizeof(es_identify_old), es_identify_patch, sizeof(es_identify_patch), 2);
		count += apply_patch("hash_check", hash_old, sizeof(hash_old), hash_patch, sizeof(hash_patch), 1);
		count += apply_patch("new_hash_check", new_hash_old, sizeof(new_hash_old), hash_patch, sizeof(hash_patch), 1);
		count += apply_patch("version_check", version_check, sizeof(version_check), version_patch, sizeof(version_patch), 0);
		
		/*count += apply_patch("MEM2_prot", MEM2_prot_old, sizeof(MEM2_prot_old), MEM2_prot_patch, sizeof(MEM2_prot_patch), 0);
		count += apply_patch("ES_OpenTitleContent1", ES_OpenTitleContent1_old, sizeof(ES_OpenTitleContent1_old), ES_OpenTitleContent1_patch, sizeof(ES_OpenTitleContent1_patch), 0);
		count += apply_patch("ES_OpenTitleContent2", ES_OpenTitleContent2_old, sizeof(ES_OpenTitleContent2_old), ES_OpenTitleContent2_patch, sizeof(ES_OpenTitleContent2_patch), 0);
		count += apply_patch("ES_ReadContent_prot", ES_ReadContent_old, sizeof(ES_ReadContent_old), ES_ReadContent_patch, sizeof(ES_ReadContent_patch), 0);
		count += apply_patch("ES_CloseContent", ES_CloseContent_old, sizeof(ES_CloseContent_old), ES_CloseContent_patch, sizeof(ES_CloseContent_patch), 0);
		count += apply_patch("ES_TitleDeleteCheck", ES_TitleDeleteCheck_old, sizeof(ES_TitleDeleteCheck_old), ES_TitleDeleteCheck_patch, sizeof(ES_TitleDeleteCheck_patch), 0);*/
		
		count += apply_patch("Kill_AntiSysTitleInstallv3_pt1", Kill_AntiSysTitleInstallv3_pt1_old, sizeof(Kill_AntiSysTitleInstallv3_pt1_old), Kill_AntiSysTitleInstallv3_pt1_patch, sizeof(Kill_AntiSysTitleInstallv3_pt1_patch), 0);
		count += apply_patch("Kill_AntiSysTitleInstallv3_pt2", Kill_AntiSysTitleInstallv3_pt2_old, sizeof(Kill_AntiSysTitleInstallv3_pt2_old), Kill_AntiSysTitleInstallv3_pt2_patch, sizeof(Kill_AntiSysTitleInstallv3_pt2_patch), 0);
		count += apply_patch("Kill_AntiSysTitleInstallv3_pt3", Kill_AntiSysTitleInstallv3_pt3_old, sizeof(Kill_AntiSysTitleInstallv3_pt3_old), Kill_AntiSysTitleInstallv3_pt3_patch, sizeof(Kill_AntiSysTitleInstallv3_pt3_patch), 0);
	}
	return count;
}
