/*******************************************************************************
 * yabdm.c                                                                     *
 *                                                                             *
 * Copyright (c) 2009 Nicksasa                                                 *
 *                                                                             *
 * Modified by DarkMatterCore [PabloACZ] (2013-2014)                           *
 *                                                                             *
 * Distributed under the terms of the GNU General Public License (v2)          *
 * See http://www.gnu.org/licenses/gpl-2.0.txt for more info.                  *
 *                                                                             *
 *******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <ogcsys.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <gccore.h>
#include <sys/fcntl.h>
#include <ogc/isfs.h>
#include <fcntl.h>
#include <dirent.h>

#include "yabdm.h"
#include "tools.h"
#include "aes.h"
#include "sha1.h"
#include "otp.h"
#include "../build/cert_sys.h"

const u8 commonkey[16] = { 0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7 };
const u8 sd_key[16] = { 0xab, 0x01, 0xb9, 0xd8, 0xe1, 0x62, 0x2b, 0x08, 0xaf, 0xba, 0xd8, 0x4d, 0xbf, 0xc2, 0xa5, 0x5d };
const u8 sd_iv[16] = { 0x21, 0x67, 0x12, 0xe6, 0xaa, 0x1f, 0x68, 0x9f, 0x95, 0xc5, 0xa2, 0x23, 0x24, 0xdc, 0x6a, 0x98 };

u8 region;
char titlename[64], ascii_id[5];
bool ftik = false, ftmd = false, change_region = false, ascii = false;

bool MakeDir(const char *Path)
{
	// Open Target Folder
	DIR* dir = opendir(Path);

	// Already Exists?
	if (dir == NULL)
	{
		// Create
		mode_t Mode = 0777;
		mkdir(Path, Mode);
		
		// Re-Verify
		closedir(dir);
		dir = opendir(Path);
		if (dir == NULL) return false;
	}

	// Success
	closedir(dir);
	return true;
}

// Creates the required folders for a filepath
// Example: Input "sd:/YABDM/00000001/test.bin" creates "sd:/YABDM" and "sd:/YABDM/00000001"

bool create_folders(char *path)
{
	char *last = strrchr(path, '/');
	char *next = strchr(path,'/');
	if (last == NULL) return true;
	
	char buf[256];
	
	while (next != last)
	{
		next = strchr((char *)(next+1),'/');
		snprintf(buf, (u32)(next-path+1), path);
		if (!MakeDir(buf)) return false;
	}
	
	return true;
}

void *allocate_memory(u32 size)
{
	return memalign(32, (size+63)&(~63));
}

s32 __FileCmp(const void *a, const void *b)
{
	dirent_t *hdr1 = (dirent_t *)a;
	dirent_t *hdr2 = (dirent_t *)b;
	
	/* Compare entries */
	if (hdr1->type == DIRENT_T_DIR && hdr2->type == DIRENT_T_FILE)
	{
		return -1;
	} else
	if (hdr1->type == DIRENT_T_FILE && hdr2->type == DIRENT_T_DIR)
	{
		return 1;
	}
	
	return stricmp(hdr1->name, hdr2->name);
}

int isdir(char *path)
{
	s32 res;
	u32 num = 0;
	
	res = ISFS_ReadDir(path, NULL, &num);
	
	if (res < 0) return 0;
	
	return 1;
}

u16 get_version(u64 titleid)
{
	s32 ret;
	u32 tmd_size;
	u16 version;
	signed_blob *tmdbuf = NULL;
	
	ret = ES_GetStoredTMDSize(titleid, &tmd_size);
	if (ret < 0)
	{
		//printf("ES_GetStoredTMDSize for '%08x-%08x' failed (%d).\n", TITLE_UPPER(titleid), TITLE_LOWER(titleid), ret);
		logfile("ES_GetStoredTMDSize for '%08x-%08x' failed (%d).\r\n", TITLE_UPPER(titleid), TITLE_LOWER(titleid), ret);
		return 0;
	}
	
	tmdbuf = allocate_memory(tmd_size);
	
	ret = ES_GetStoredTMD(titleid, tmdbuf, tmd_size);
	if (ret < 0)
	{
		//printf("ES_GetStoredTMD for '%08x-%08x' failed (%d).\n", TITLE_UPPER(titleid), TITLE_LOWER(titleid), ret);
		logfile("ES_GetStoredTMD for '%08x-%08x' failed (%d).\r\n", TITLE_UPPER(titleid), TITLE_LOWER(titleid), ret);
		free(tmdbuf);
		return 0;
	}
	
	version = ((tmd*)SIGNATURE_PAYLOAD(tmdbuf))->title_version;
	logfile("version = %u\r\n", version);
	free(tmdbuf);
	
	return version;
}

s32 getdir_info(char *path, dirent_t **ent, u32 *cnt)
{
	s32 res;
	u32 num = 0;
	char pbuf[ISFS_MAXPATH + 1], ebuf[ISFS_MAXPATH + 1];
	
	int i, j, k;
	
	logfile("\r\n[GETDIR_INFO] Path = %s. ", path);
	
	/* Get number of entries in this directory */
	res = ISFS_ReadDir(path, NULL, &num);
	if (res != ISFS_OK)
	{
		//printf("Error: could not get dir entry count! (result: %d)\n", res);
		logfile("\r\nError: could not get dir entry count! (result: %d).\r\n", res);
		return -1;
	}
	
	/* No entries found */
	if (num == 0)
	{
		logfile("No files/directories found.\r\n");
		return -1;
	}
	
	/* Allocate memory for the name list */
	char *nbuf = (char *)allocate_memory((ISFS_MAXPATH + 1) * num);
	if (nbuf == NULL)
	{
		//printf("Error: could not allocate buffer for name list!\n");
		logfile("\r\nError: could not allocate buffer for name list!\r\n");
		return -1;
	}
	
	/* Read entries */
	res = ISFS_ReadDir(path, nbuf, &num);
	if (res != ISFS_OK)
	{
		//printf("Error: could not get name list! (result: %d)\n", res);
		logfile("\r\nError: could not get name list! (result: %d).\r\n", res);
		return -1;
	}
	
	/* Save number of entries */
	*cnt = num;
	
	/* Avoid a possible buffer overflow by freeing the entry buffer before reusing it */
	if (*ent != NULL) free(*ent);
	*ent = allocate_memory(sizeof(dirent_t) * num);
	if (*ent == NULL)
	{
		logfile("Error allocating memory for the entry buffer!\r\n");
		free(nbuf);
		return -1;
	}
	
	logfile("Directory list:\r\n");
	for(i = 0, k = 0; i < num; i++)
	{
		for (j = 0; nbuf[k] != 0; j++, k++) ebuf[j] = nbuf[k];
		ebuf[j] = 0;
		k++;
		
		snprintf((*ent)[i].name, MAX_CHARACTERS((*ent)[i].name), ebuf);
		snprintf(pbuf, MAX_CHARACTERS(pbuf), "%s/%s", path, ebuf);
		logfile("%s\r\n", pbuf);
		(*ent)[i].type = ((isdir(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
		
		if (strncmp(path, "/title/00010000", 15) == 0)
		{
			(*ent)[i].function = TYPE_SAVEDATA;
		}
		
		if (strncmp(path, "/title/00010001", 15) == 0)
		{
			(*ent)[i].function = TYPE_TITLE;
		}
		
		if (strncmp(path, "/title/00000001", 15) == 0)
		{
			(*ent)[i].function = TYPE_IOS;
		}
		
		if (strncmp(path, "/title/00010002", 15) == 0)
		{
			(*ent)[i].function = TYPE_SYSTITLE;
		}
		
		if (strncmp(path, "/title/00010004", 15) == 0)
		{
			(*ent)[i].function = TYPE_GAMECHAN;
		}
		
		if (strncmp(path, "/title/00010005", 15) == 0)
		{
			(*ent)[i].function = TYPE_DLC;
		}
		
		if (strncmp(path, "/title/00010008", 15) == 0)
		{
			(*ent)[i].function = TYPE_HIDDEN;
		}
		
		if ((strncmp(ebuf, "content", 7) == 0) || (strncmp(ebuf, "data", 4) == 0) || \
			(strstr(path, "content") != 0) || (strstr(path, "data") != 0))
		{
			(*ent)[i].function = TYPE_OTHER;
		}
	}
	
	logfile("\r\n");
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	free(nbuf);
	
	return 0;
}

s32 __convertWiiString(char *str, u8 *data, u32 cnt)
{
	u32 i;
	
	for(i = 0; i < cnt; data += 2)
	{
		u16 *chr = (u16*)data;
		if (*chr == 0)
		{
			break;
		} else {
			str[i] = *chr;
		}
		
		i++;
	}
	str[i] = 0;

	return 0;
}

char *read_title_name(u64 titleid, bool get_description)
{
	bool is_dlc;
	s32 ret, cfd;
	u32 num, cnt;
	dirent_t *list = NULL;
	char path[ISFS_MAXPATH] ATTRIBUTE_ALIGN(32);
	static fstats status ATTRIBUTE_ALIGN(32);
	
	u8 wibn_magic[4] = { 0x57, 0x49, 0x42, 0x4E };
	u8 imet_magic[4] = { 0x49, 0x4D, 0x45, 0x54 };
	
	u8 *buffer = allocate_memory(sizeof(IMET));
	if (!buffer)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\r\n");
		goodbye();
	}
	
	memset(buffer, 0x00, sizeof(IMET));
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	snprintf(titlename, MAX_CHARACTERS(titlename), "Channel/Title deleted from Wii Menu? (couldn't get info)");
	
	ret = getdir_info(path, &list, &num);
	if (ret < 0)
	{
		//printf("Reading folder of the title failed.\n");
		logfile("Reading folder of the title failed.\r\n");
		if (list) free(list);
		return titlename;
	}
	
	for (cnt = 0; cnt < num; cnt++)
	{
		/* Only open files with the ".app" extension */
		if (stricmp(list[cnt].name + strlen(list[cnt].name) - 4, ".app") == 0) 
		{
			memset(buffer, 0x00, 4);
			snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content/%s", TITLE_UPPER(titleid), TITLE_LOWER(titleid), list[cnt].name);
			
			cfd = ISFS_Open(path, ISFS_OPEN_READ);
			if (cfd < 0)
			{
				//printf("ISFS_Open for '%s' failed (%d).\n", path, cfd);
				logfile("ISFS_Open for '%s' failed (%d).\r\n", path, cfd);
				continue;
			}
			
			ret = ISFS_GetFileStats(cfd, &status);
			if (ret < 0)
			{
				//printf("ISFS_GetFileStats(fd) returned %d.\n", ret);
				logfile("ISFS_GetFileStats(fd) returned %d.\r\n", ret);
				ISFS_Close(cfd);
				continue;
			}
			
			if (status.file_length > 0x80)
			{
				ISFS_Seek(cfd, 0x40, 0);
				
				ret = ISFS_Read(cfd, buffer, 4);
				if (ret < 0)
				{
					//printf("ISFS_Read(wibn_magic) returned %d.\n", ret);
					logfile("ISFS_Read(wibn_magic) returned %d.\r\n", ret);
					ISFS_Close(cfd);
					continue;
				}
				
				if (memcmp(buffer, wibn_magic, 4) == 0)
				{
					is_dlc = true;
					ISFS_Seek(cfd, 0x40, 0);
				} else {
					ISFS_Seek(cfd, 0x80, 0);
					
					ret = ISFS_Read(cfd, buffer, 4);
					if (ret < 0)
					{
						//printf("ISFS_Read(imet_magic) returned %d.\n", ret);
						logfile("ISFS_Read(imet_magic) returned %d.\r\n", ret);
						ISFS_Close(cfd);
						continue;
					}
					
					if (memcmp(buffer, imet_magic, 4) == 0)
					{
						is_dlc = false;
						ISFS_Seek(cfd, 0, 0);
					} else {
						/* No dice, check the next file */
						ISFS_Close(cfd);
						continue;
					}
				}
				
				ret = ISFS_Read(cfd, buffer, (is_dlc ? sizeof(WIBN) : sizeof(IMET)));
				if (ret < 0)
				{
					//printf("ISFS_Read(buffer) returned %d.\n", ret);
					logfile("ISFS_Read(buffer) returned %d.\r\n", ret);
					ISFS_Close(cfd);
					free(list);
					free(buffer);
					return titlename;
				}
				
				ISFS_Close(cfd);
				
				if (is_dlc)
				{
					WIBN *dlc_data = allocate_memory(sizeof(WIBN));
					if (!dlc_data)
					{
						//printf("Error allocating memory for dlc_data.\n");
						logfile("Error allocating memory for dlc_data.\r\n");
						ISFS_Close(cfd);
						free(list);
						free(buffer);
						goodbye();
					}
					
					memcpy(dlc_data, buffer, sizeof(WIBN));
					
					/* Convert string to ASCII */
					__convertWiiString(titlename, dlc_data->name, 0x40);
					
					if (get_description)
					{
						char description[64];
						__convertWiiString(description, dlc_data->desc, 0x40);
						if (strlen(description) > 1) snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", titlename, description);
					}
					
					free(dlc_data);
				} else {
					u32 i;
					char str[20][42];
					
					IMET *banner_data = allocate_memory(sizeof(IMET));
					if (!banner_data)
					{
						//printf("Error allocating memory for banner_data.\n");
						logfile("Error allocating memory for banner_data.\r\n");
						ISFS_Close(cfd);
						free(list);
						free(buffer);
						goodbye();
					}
					
					memcpy(banner_data, buffer, sizeof(IMET));
					
					/* Convert strings to ASCII */
					for (i = 0; i < 20; i++) __convertWiiString(str[i], banner_data->names[i], 0x2A);
					
					/* Try to get the appropiate string for the console language */
					if (strlen(str[lang * 2]) > 1)
					{
						if (get_description && strlen(str[(lang * 2) + 1]) > 1)
						{
							snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", str[lang * 2], str[(lang * 2) + 1]);
						} else {
							snprintf(titlename, MAX_CHARACTERS(titlename), str[lang * 2]);
						}
					} else {
						/* Default to English */
						if (get_description && strlen(str[3]) > 1)
						{
							snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", str[2], str[3]);
						} else {
							snprintf(titlename, MAX_CHARACTERS(titlename), str[2]);
						}
					}
					
					free(banner_data);
				}
				
				free(list);
				free(buffer);
				
				return titlename;
			} else {
				ISFS_Close(cfd);
			}
		}
	}
	
	free(list);
	free(buffer);
	
	return titlename;
}

char *read_save_name(u64 titleid, bool get_description)
{
	s32 cfd, ret;
    char path[ISFS_MAXPATH] ATTRIBUTE_ALIGN(32);
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/data/banner.bin", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	snprintf(titlename, MAX_CHARACTERS(titlename), "Channel/Title deleted from Wii Menu? (couldn't get info)");
	
	cfd = ISFS_Open(path, ISFS_OPEN_READ);
	if (cfd < 0)
	{
		//printf("ISFS_Open for '%s' failed (%d).\n", path, cfd);
		logfile("ISFS_Open for '%s' failed (%d).\r\n", path, cfd);
		return titlename;
	}
	
	WIBN *save_data = allocate_memory(sizeof(WIBN));
	if (save_data == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\r\n");
		goodbye();
	}
	
	ret = ISFS_Read(cfd, save_data, sizeof(WIBN));
	if (ret < 0)
	{
		//printf("ISFS_Read for '%s' failed (%d).\n", path, ret);
		logfile("ISFS_Read for '%s' failed (%d).\r\n", path, ret);
		ISFS_Close(cfd);
		free(save_data);
		return titlename;
	}
	
	ISFS_Close(cfd);
	
	/* Convert string to ASCII */
	__convertWiiString(titlename, save_data->name, 0x40);
	
	if (get_description)
	{
		char description[64];
		__convertWiiString(description, save_data->desc, 0x40);
		if (strlen(description) > 1) snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", titlename, description);
	}
	
	free(save_data);
	
	return titlename;
}

char *get_name(u64 titleid, bool get_description)
{
	char *temp;
	
	if (TITLE_UPPER(titleid) == 0x00010000 && TITLE_LOWER(titleid) != 0x48415a41)
	{
		temp = read_save_name(titleid, get_description);
	} else {
		temp = read_title_name(titleid, get_description);
		if (strncmp(temp, "Channel/Title deleted from Wii Menu? (couldn't get info)", 56) == 0)
		{
			temp = read_save_name(titleid, get_description);
		}
	}
	
	return temp;
}

char *read_cntbin_name(FILE *cnt_bin, bool get_description)
{
	u32 i;
	int ret;
	char str[20][42];
	
	IMET *buf = allocate_memory(sizeof(IMET));
	if (buf == NULL)
	{
		//printf("\nError allocating memory for buf.\n");
		logfile("\r\nError allocating memory for buf.\r\n");
		fclose(cnt_bin);
		goodbye();
	}
	
	fread(buf, sizeof(IMET), 1, cnt_bin);
	
	ret = aes_128_cbc_decrypt(sd_key, sd_iv, (u8*)buf, sizeof(IMET));
	if (ret < 0)
	{
		//printf("\nError decrypting data.\n");
		logfile("\r\nError decrypting data.\r\n");
		free(buf);
		snprintf(titlename, MAX_CHARACTERS(titlename), "Unknown (couldn't get info)");
		return titlename;
	}
	
	/* Convert strings to ASCII */
	for (i = 0; i < 20; i++) __convertWiiString(str[i], buf->names[i], 0x2A);
	
	/* Try to get the appropiate string for the console language */
	if (strlen(str[lang * 2]) > 1)
	{
		if (get_description && strlen(str[(lang * 2) + 1]) > 1)
		{
			snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", str[lang * 2], str[(lang * 2) + 1]);
		} else {
			snprintf(titlename, MAX_CHARACTERS(titlename), str[lang * 2]);
		}
	} else {
		/* Default to English */
		if (get_description && strlen(str[3]) > 1)
		{
			snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", str[2], str[3]);
		} else {
			snprintf(titlename, MAX_CHARACTERS(titlename), str[2]);
		}
	}
	
	free(buf);
	
	return titlename;
}

u32 pad_data(void *ptr, u32 len, bool pad_16)
{
	u32 new_size = (pad_16 ? round16(len) : round64(len));
	u32 diff = new_size - len;
	
	if (diff > 0 && malloc_usable_size(ptr) > len) memset(ptr + len, 0x00, diff);
	
	return new_size;
}

s32 read_isfs(char *path, u8 **out, u32 *size)
{
	s32 ret, fd;
	static fstats status ATTRIBUTE_ALIGN(32);
	
	fd = ISFS_Open(path, ISFS_OPEN_READ);
	if (fd < 0)
	{
		//printf("ISFS_Open for '%s' returned %d.\n", path, fd);
		logfile("ISFS_Open for '%s' returned %d.\r\n", path, fd);
		return -1;
	}
	
	ret = ISFS_GetFileStats(fd, &status);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("ISFS_GetFileStats(fd) returned %d.\r\n", ret);
		ISFS_Close(fd);
		return -1;
	}
	
	if (status.file_length == 0)
	{
		ISFS_Close(fd);
		return -1;
	}
	
	*size = status.file_length;
	logfile("Size = %u bytes.\r\n", *size);
	
	*out = allocate_memory(*size);
	if (*out == NULL) 
	{ 
		//printf("Error allocating memory for out.\n");
		logfile("\r\nError allocating memory for out.\r\n");
		ISFS_Close(fd);
		goodbye();
	}
	
	u32 blksize, writeindex = 0, restsize = *size;
	
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			blksize = BLOCKSIZE;
		} else {
			blksize = restsize;
		}
		
		ret = ISFS_Read(fd, *out + writeindex, blksize);
		if (ret < 0) 
		{
			//printf("\nISFS_Read(%d, %d) returned %d.\n", fd, blksize, ret);
			logfile("\r\nISFS_Read(%d, %d) returned %d.\r\n", fd, blksize, ret);
			free(*out);
			ISFS_Close(fd);
			return -1;
		}
		
		writeindex += blksize;
		restsize -= blksize;
	}
	
	ISFS_Close(fd);
	return 0;
}

void zero_sig(signed_blob *sig)
{
	u8 *sig_ptr = (u8 *)sig;
	memset(sig_ptr + 4, 0, SIGNATURE_SIZE(sig)-4);
}

void brute_tmd(tmd *p_tmd)
{
	u16 fill;
	for (fill = 0; fill < 65535; fill++)
	{
		p_tmd->fill3 = fill;
		sha1 hash;
		//logfile("\r\nSHA1(%p, %x, %p)\r\n", p_tmd, TMD_SIZE(p_tmd), hash);
		SHA1((u8 *)p_tmd, TMD_SIZE(p_tmd), hash);
		
		if (hash[0]==0)
		{
			//logfile("Setting fill3 to %04hx... ", fill);
			break;
		}
	}
}

void brute_tik(tik *p_tik)
{
	u16 fill;
	for (fill = 0; fill < 65535; fill++)
	{
		p_tik->padding = fill;
		sha1 hash;
		//logfile("\r\nSHA1(%p, %x, %p)\r\n", p_tmd, TMD_SIZE(p_tmd), hash);
		SHA1((u8 *)p_tik, sizeof(tik), hash);
		
		if (hash[0]==0)
		{
			//logfile("Setting padding to %04hx... ", fill);
			break;
		}
	}
}

bool check_if_fakesigned(signed_blob *data)
{
	u32 *sig = (u32 *)data;
	if (sig[4] == 0) return true;
	return false;
}

void forge(signed_blob *data, bool is_tmd, bool verbose)
{
	if (!check_if_fakesigned(data))
	{
		zero_sig(data);
		
		if (is_tmd)
		{
			brute_tmd(SIGNATURE_PAYLOAD(data));
		} else {
			brute_tik(SIGNATURE_PAYLOAD(data));
		}
		
		if (verbose)
		{
			printf("Forged %s signature. ", (is_tmd ? "TMD" : "Ticket"));
			logfile("Forged %s signature. ", (is_tmd ? "TMD" : "Ticket"));
		}
	} else {
		if (verbose)
		{
			printf("%s already fakesigned. ", (is_tmd ? "TMD" : "Ticket"));
			logfile("%s already fakesigned. ", (is_tmd ? "TMD" : "Ticket"));
		}
	}
	
	u8 *ptr = (u8*)data;
	if (is_tmd && change_region)
	{
		/* Change WAD region */
		ptr[0x19D] = region;
		if (verbose)
		{
			printf("Region changed to 0x%02x. ", region);
			logfile("Region changed to 0x%02x. ", region);
		}
	} else
	if (!is_tmd)
	{
		/* Wipe Console ID and ECDH data to avoid installation errors on other Wiis */
		memset(ptr + 0x180, 0, 0x3C);
		memset(ptr + 0x1D8, 0, 4);
	}
}

s32 GetTMD(FILE *f, u64 id, signed_blob **tmd)
{
	s32 ret;
	u32 tmd_size;
	
	ret = ES_GetStoredTMDSize(id, &tmd_size);
	if (ret < 0)
	{
		//printf("ES_GetStoredTMDSize for '%08x-%08x' failed (%d).\n", TITLE_UPPER(id), TITLE_LOWER(id), ret);
		logfile("ES_GetStoredTMDSize for '%08x-%08x' failed (%d).\r\n", TITLE_UPPER(id), TITLE_LOWER(id), ret);
		return -1;
	}
	
	logfile("TMD size = %u.\r\n", tmd_size);
	header->tmd_len = tmd_size;
	*tmd = allocate_memory(tmd_size);
	
	ret = ES_GetStoredTMD(id, *tmd, tmd_size);
	if (ret < 0)
	{
		//printf("ES_GetStoredTMD for '%08x-%08x' failed (%d).\n", TITLE_UPPER(id), TITLE_LOWER(id), ret);
		logfile("ES_GetStoredTMD for '%08x-%08x' failed (%d).\r\n", TITLE_UPPER(id), TITLE_LOWER(id), ret);
		free(*tmd);
		return -1;
	}
	
	if ((tmd_size % 64) != 0)
	{
		tmd_size = pad_data(*tmd, tmd_size, false);
		logfile("Padded TMD size = %u.\r\n", tmd_size);
	}
	
	/* Fakesign TMD if the user chose to */
	if (ftmd) forge(*tmd, true, true);
	
	/* Write to output WAD */
	fwrite(*tmd, tmd_size, 1, f);
	
	return 0;
}	

s32 GetTicket(FILE *f, u64 id, signed_blob **tik)
{
	u32 tik_size;
	u8 *buffer;
	char path[ISFS_MAXPATH];
	
	snprintf(path, MAX_CHARACTERS(path), "/ticket/%08x/%08x.tik", TITLE_UPPER(id), TITLE_LOWER(id));
	
	logfile("Ticket path is '%s'.\r\n", path);
	s32 ret = read_isfs(path, &buffer, &tik_size);
	if (ret < 0)
	{
		printf("Error getting Ticket!\n");
		return -1;
	}
	
	if (tik_size > 0x2A4)
	{
		tik_size = 0x2A4;
		logfile("Ticket size reduced to 0x2A4 (multiple tickets).\r\n");
	}
	
	header->tik_len = tik_size;
	
	if ((tik_size % 64) != 0)
	{
		tik_size = pad_data(buffer, tik_size, false);
		logfile("Padded Ticket size = %u.\r\n", tik_size);
	}
	
	/* Fakesign ticket if the user chose to */
	if (ftik) forge((signed_blob *)buffer, false, true);
	
	/* Change the common key index to '00' */
	/* Useful to avoid installation errors with WADs dumped from vWii or a Korean Wii */
	if ((buffer[0x1F1] == 0x01) || (buffer[0x1F1] == 0x02)) buffer[0x1F1] = 0x00;
	
	/* Write to output WAD */
	fwrite(buffer, tik_size, 1, f);
	
	*tik = (signed_blob *)buffer;
	
	return 0;
}	

void GetCerts(FILE *f)
{
	if (cert_sys_size != 2560)
	{
		printf("Couldn't get '/sys/cert.sys'. Exiting...");
		logfile("Couldn't get '/sys/cert.sys'. Exiting...");
		goodbye();
	}
	
	fwrite(cert_sys, cert_sys_size, 1, f);
	
	header->certs_len = cert_sys_size;
}

s32 GetContent(FILE *f, u64 id, u16 content, u8* key, u16 index, u32 size, u8 *hash)
{
	char path[ISFS_MAXPATH];
	
	/* Used to hold the current state of the SHA-1 hash during calculation */
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content/%08x.app", TITLE_UPPER(id), TITLE_LOWER(id), content);
	logfile("Regular content path is '%s'.\r\n", path);
	printf("Adding regular content %08x.app... ", content);
	logfile("TMD hash: ");
	hex_key_dump(hash, 20);
	logfile("\r\n");
	
	s32 fd = ISFS_Open(path, ISFS_OPEN_READ);
	if (fd < 0)
	{
		logfile("ISFS_Open for '%s' returned %d.\r\n", path, fd);
		return fd;
	}
	
	u32 blksize = BLOCKSIZE; // 16 KB
	
	u8 *buffer = allocate_memory(blksize);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\r\n");
		ISFS_Close(fd);
		fclose(f);
		goodbye();
	}
	
	int ret = 0;
	u32 i, size2 = 0;
	
	static u8 iv[16];
	memset(iv, 0, 16);
	memcpy(iv, &index, 2);
	
	logfile("Writing... ");
	for (i = 0; i < size; i += blksize)
	{
		if (blksize > size - i) blksize = size - i;
		
		/* Save the last 16 bytes of the previous encrypted chunk to use them as the IV for the next one */
		if (i > 0) memcpy(iv, &(buffer[BLOCKSIZE - 16]), 16);
		
		ret = ISFS_Read(fd, buffer, blksize);
		if (ret < 0) break;
		
		/* Hash current data block */
		SHA1Update(&ctx, buffer, blksize);
		
		/* Pad data to a 16-byte boundary (required for the encryption process). Probably only needed for the last chunk */
		if ((blksize % 16) != 0) blksize = pad_data(buffer, blksize, true);
		
		ret = aes_128_cbc_encrypt(key, iv, buffer, blksize);
		if (ret < 0) break;
		
		/* Pad data to a 64-byte boundary (required for the WAD alignment). Again, probably only needed for the last chunk */
		if ((blksize % 64) != 0) blksize = pad_data(buffer, blksize, false);
		
		fwrite(buffer, blksize, 1, f);
		
		size2 += blksize;
	}
	
	free(buffer);
	ISFS_Close(fd);
	
	sha1 cnthash;
	SHA1Final(cnthash, &ctx);
	logfile("Dumped content hash: ");
	hex_key_dump(cnthash, 20);
	logfile("\r\n");
	
	if (memcmp(hash, cnthash, 20) != 0)
	{
		printf("\nError: hash didn't match!\n");
		logfile("Error: hash didn't match!\r\n");
		if (ret >= 0) ret = -1;
	}
	
	if (ret < 0) return ret;
	
	logfile("Content added successfully. Original content size: %u bytes. size2: %u bytes.\r\n", size, size2);
	printf("done.\n");
	
	header->data_len += size2;
	return 0;
}

void GetContentMap()
{
	s32 fd, ret;
	void *buf = NULL;
	static fstats status ATTRIBUTE_ALIGN(32);
	logfile("Reading '/shared1/content.map'... ");
	
	fd = ISFS_Open("/shared1/content.map", ISFS_OPEN_READ);
	ret = ISFS_GetFileStats(fd, &status);
	
	if (fd < 0 || ret < 0)
	{
		printf("\nError opening '/shared1/content.map' for reading.");
		logfile("\r\nError opening '/shared1/content.map' for reading.");
		goodbye();
	}
	
	content_map_size = status.file_length;
	
	logfile("content.map size = %u bytes.\r\nWriting '/shared1/content.map' to memory buffer... ", content_map_size);
	buf = allocate_memory(content_map_size);
	if (buf != NULL)
	{
		ISFS_Read(fd, (char*)buf, content_map_size);
		logfile("done.\r\n");
	}
	
	ISFS_Close(fd);
	
	cm = (map_entry_t*)buf;
}

s32 GetSharedContent(FILE *f, u8* key, u16 index, u8* hash, map_entry_t *cm, u32 elements)
{
	u8 *shared_buf;
	u32 i, shared_size;
	bool found = false;
	char path[32] ATTRIBUTE_ALIGN(32);
	int ret;
	
	printf("Adding shared content... ");
	for (i = 0; i < elements; i++)
	{
		if(memcmp(cm[i].sha1, hash, 20) == 0)
		{
			found = true;
			snprintf(path, MAX_CHARACTERS(path), "/shared1/%.8s.app", cm[i].filename);
			logfile("Found shared content! Path is '%s'.\r\nReading... ", path);
			ret = read_isfs(path, &shared_buf, &shared_size);
			if (ret < 0) return -1;
			logfile("done.\r\n");
			
			/* Required for the encryption process */
			if ((shared_size % 16) != 0)
			{
				logfile("Padding decrypted data to a 16-byte boundary... ");
				shared_size = pad_data(shared_buf, shared_size, true);
				logfile("done. New size: %u bytes.\r\n", shared_size);
			}
			
			static u8 iv[16];
			memset(iv, 0, 16);
			memcpy(iv, &index, 2);
			
			ret = aes_128_cbc_encrypt(key, iv, shared_buf, shared_size);
			if (ret < 0)
			{
				free(shared_buf);
				return -1;
			}
			
			/* Required for the WAD alignment */
			if ((shared_size % 64) != 0)
			{
				logfile("Padding encrypted data to a 64-byte boundary... ");
				shared_size = pad_data(shared_buf, shared_size, false);
				logfile("done. New size: %u bytes.\r\n", shared_size);
			}
			
			logfile("Writing... ");
			u32 writeindex = 0;
			u32 restsize = shared_size;
			while (restsize > 0)
			{
				if (restsize >= SD_BLOCKSIZE)
				{
					fwrite(&(shared_buf[writeindex]), SD_BLOCKSIZE, 1, f);
					restsize = restsize - SD_BLOCKSIZE;
					writeindex = writeindex + SD_BLOCKSIZE;
				} else {
					fwrite(&(shared_buf[writeindex]), restsize, 1, f);
					restsize = 0;
				}
			}
			logfile("done. Content added successfully.\r\n");
			
			header->data_len += shared_size;
			free(shared_buf);
			break;
		}
	}
	
	if (found == false)
	{
		printf("\nCould not find the shared content, no hash did match!");
		logfile("Could not find the shared content, no hash did match!\r\n");
		logfile("\r\nSHA1 of not found content: ");
		hex_key_dump(hash, 20);
		return -1;
	}
	
	printf("done.\n");
	return 0;
}

s32 GetContentFromCntBin(FILE *cnt_bin, FILE *wadout, u16 index, u32 size, u8 *key, u8 *hash)
{
	u32 rounded_size = round64(size);
	u32 blksize = SD_BLOCKSIZE; // 32 KB
	
	/* Used to hold the current state of the SHA-1 hash during calculation */
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	
	logfile("TMD hash: ");
	hex_key_dump(hash, 20);
	logfile("\r\n");
	
	u8 *buffer = allocate_memory(blksize);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\r\n");
		fclose(cnt_bin);
		fclose(wadout);
		goodbye();
	}
	
	int ret = 0;
	u32 i;
	
	static u8 iv1[16];
	memset(iv1, 0, 16);
	memcpy(iv1, &index, 2);
	
	static u8 iv2[16];
	memset(iv2, 0, 16);
	memcpy(iv2, &index, 2);
	
	logfile("Writing... ");
	for (i = 0; i < rounded_size; i += blksize)
	{
		if (blksize > rounded_size - i) blksize = rounded_size - i;
		
		/* Save the last 16 bytes of the previous chunk from cnt_bin to use them as the IV for aes_128_cbc_decrypt */
		if (i > 0)
		{
			fseek(cnt_bin, -16, SEEK_CUR);
			fread(iv1, 16, 1, cnt_bin);
		}
		
		fread(buffer, blksize, 1, cnt_bin);
		
		ret = aes_128_cbc_decrypt(prng_key, iv1, buffer, blksize);
		if (ret < 0) break;
		
		/* Hash current data block */
		SHA1Update(&ctx, buffer, blksize);
		
		/* Only do this if the content needs padding */
		if ((rounded_size - size) > 0)
		{
			/* Check if this is the last chunk */
			if ((i + blksize - (rounded_size - size)) == size)
			{
				/* Pad data to a 16-byte boundary (required for the encryption process) */
				blksize -= (rounded_size - size);
				if ((blksize % 16) != 0) blksize = pad_data(buffer, blksize, true);
			}
		}
		
		ret = aes_128_cbc_encrypt(key, iv2, buffer, blksize);
		if (ret < 0) break;
		
		/* Save the last 16 bytes of the previous encrypted chunk to use them as the IV for aes_128_cbc_encrypt */
		memcpy(iv2, &(buffer[SD_BLOCKSIZE - 16]), 16);
		
		/* Pad data to a 64-byte boundary (required for the WAD alignment). Probably only needed for the last chunk */
		if ((blksize % 64) != 0) blksize = pad_data(buffer, blksize, false);
		
		fwrite(buffer, blksize, 1, wadout);
	}
	
	free(buffer);
	
	sha1 cnthash;
	SHA1Final(cnthash, &ctx);
	logfile("Dumped content hash: ");
	hex_key_dump(cnthash, 20);
	logfile("\r\n");
	
	if (memcmp(hash, cnthash, 20) != 0)
	{
		printf("\nError: hash didn't match!\n");
		logfile("Error: hash didn't match!\r\n");
		if (ret >= 0) ret = -1;
	}
	
	if (ret < 0) return ret;
	
	logfile("Content added successfully. Original content size: %u bytes. rounded_size: %u bytes.\r\n", size, rounded_size);
	printf("done.\n");
	
	header->data_len += rounded_size;
	return 0;
}

int isdir_device(char *path)
{
	DIR* dir = opendir(path);
	if(dir == NULL) return 0;
	
	closedir(dir);
	
	return 1;
}

s32 getdir_device(char *path, dirent_t **ent, u32 *cnt)
{
	logfile("\r\n[GETDIR_DEVICE] Path = %s. ", path);
	
	u32 i = 0;
	DIR *dip;
    struct dirent *dit;
	char pbuf[ISFS_MAXPATH + 1] = {0};
	
	if ((dip = opendir(path)) == NULL)
    {
		//printf("\nError opening '%s'.\n", path);
		logfile("\r\nError opening '%s'.\r\n", path);
        return -1;
    }
	
    while ((dit = readdir(dip)) != NULL) i++;
	
	if (i == 0)
	{
		logfile("No files/directories found.\r\n");
		closedir(dip);
		return -2;
	}
	
	rewinddir(dip);
	
	if (*ent) free(*ent);
	*ent = allocate_memory(sizeof(dirent_t) * i);
	if (*ent == NULL)
	{
		logfile("Error allocating memory for the entry buffer!\r\n");
		closedir(dip);
		return -3;
	}
	
	i = 0;
	
	logfile("Directory list:\r\n");
    while ((dit = readdir(dip)) != NULL)
    {
		if (strncmp(dit->d_name, ".", 1) != 0 && strncmp(dit->d_name, "..", 2) != 0)
		{
			snprintf((*ent)[i].name, MAX_CHARACTERS((*ent)[i].name), dit->d_name);
			snprintf(pbuf, MAX_CHARACTERS(pbuf), "%s/%s", path, dit->d_name);
			logfile("%s\r\n", pbuf);
			(*ent)[i].type = ((isdir_device(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
			(*ent)[i].function = TYPE_OTHER;
			i++;
		}	
    }
	
	logfile("\r\n");
	closedir(dip);
	*cnt = i;
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	return 0;
}

s32 dumpfile(char *source, char *destination)
{
	s32 ret;
	static fstats status ATTRIBUTE_ALIGN(32);
	
	u8 *buffer = allocate_memory(BLOCKSIZE);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\r\n");
		goodbye();
	}
	
	int fd = ISFS_Open(source, ISFS_OPEN_READ);
	if (fd < 0) 
	{
		//printf("\nError: ISFS_OpenFile for '%s' returned %d.\n", source, fd);
		logfile("\r\nError: ISFS_OpenFile for '%s' returned %d.\r\n", source, fd);
		return fd;
	}

	FILE *file = fopen(destination, "wb+");
	if (!file)
	{
		//printf("\nError: fopen for '%s' returned 0 .\n", destination);
		logfile("\r\nError: fopen '%s' returned 0.\r\n", destination);
		ISFS_Close(fd);
		return -1;
	}
	
	ret = ISFS_GetFileStats(fd, &status);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("\r\nISFS_GetFileStats(fd) returned %d.\r\n", ret);
		ISFS_Close(fd);
		fclose(file);
		remove(destination);
		return ret;
	}
	
	Con_ClearLine();
	printf("Dumping '%s' / Size = %u KB", source, (status.file_length / 1024)+1);
	logfile("Dumping '%s' / Size = %u KB", source, (status.file_length / 1024)+1);
	
	u32 size, restsize = status.file_length;
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			size = BLOCKSIZE;
		} else {
			size = restsize;
		}
		
		ret = ISFS_Read(fd, buffer, size);
		if (ret < 0)
		{
			//printf("\nISFS_Read(%d, %p, %d) returned %d.\n", fd, buffer, size, ret);
			logfile("\r\nISFS_Read(%d, %p, %d) returned %d.\r\n", fd, buffer, size, ret);
			ISFS_Close(fd);
			fclose(file);
			free(buffer);
			remove(destination);
			return ret;
		}
		
		ret = fwrite(buffer, size, 1, file);
		if (ret < 0) 
		{
			//printf("\nfwrite error: %d.\n", ret);
			logfile("\r\nfwrite error: %d.\r\n", ret);
			ISFS_Close(fd);
			fclose(file);
			free(buffer);
			remove(destination);
			return ret;
		}
		
		restsize -= size;
	}
	
	ISFS_Close(fd);
	fclose(file);
	free(buffer);
	return 0;
}

s32 flash(char* source, char* destination)
{
	s32 ret, nandfile;
	//static fstats stats ATTRIBUTE_ALIGN(32);
	
	u8 *buffer = allocate_memory(BLOCKSIZE);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\r\n");
		goodbye();
	}
	
	FILE *file = fopen(source, "rb");
	if (!file) 
	{
		printf("Error opening '%s' for reading.\n", source);
		logfile("Error opening '%s' for reading.\r\n", source);
		free(buffer);
		return -1;
	}
	
	fseek(file, 0, SEEK_END);
	u32 filesize = ftell(file);
	rewind(file);

	ISFS_Delete(destination);
	ISFS_CreateFile(destination, 0, 3, 3, 3);
	
	nandfile = ISFS_Open(destination, ISFS_OPEN_RW);
	if (nandfile < 0)
	{
		//printf("ISFS_Open('%s', WRITE) error: %d.\n", destination, nandfile);
		logfile("ISFS_Open('%s', WRITE) error: %d.\r\n", destination, nandfile);
		fclose(file);
		free(buffer);
		return -1;
	}
	
	Con_ClearLine();
	printf("Flashing '%s' / Size = %u KB", destination, (filesize / 1024)+1);
	logfile("Flashing '%s' / Size = %u KB", destination, (filesize / 1024)+1);
	
	u32 size, restsize = filesize;
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			size = BLOCKSIZE;
		} else {
			size = restsize;
		}
		
		ret = fread(buffer, size, 1, file);
		if (!ret) 
		{
			//printf("Error reading data from '%s' (ret = %d).\n", source, ret);
			logfile("Error reading data from '%s' (ret = %d).\r\n", source, ret);
			ISFS_Close(nandfile);
			ISFS_Delete(destination);
			fclose(file);
			free(buffer);
			return -1;
		}
		
		ret = ISFS_Write(nandfile, buffer, size);
		if (!ret) 
		{
			//printf("ISFS_Write('%s') error: %d.\n", destination, ret);
			logfile("ISFS_Write('%s') error: %d.\r\n", destination, ret);
			ISFS_Close(nandfile);
			ISFS_Delete(destination);
			fclose(file);
			free(buffer);
			return -1;
		}
		
		restsize -= size;
	}
	
	ISFS_Close(nandfile);
	fclose(file);
	free(buffer);
	
	/*nandfile = ISFS_Open(destination, ISFS_OPEN_READ);
	if (nandfile < 0)
	{
		//printf("ISFS_Open('%s', READ) error: %d.\n", destination, nandfile);
		logfile("ISFS_Open('%s', READ) error: %d.\r\n", destination, nandfile);
		ISFS_Delete(destination);
		return -1;
	}	
	
	ret = ISFS_GetFileStats(nandfile, &stats);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("ISFS_GetFileStats(fd) returned %d.\r\n", ret);
		ISFS_Close(nandfile);
		ISFS_Delete(destination);
		return -1;
	}
	
	printf("Flashing file to NAND successful! New file is %u bytes.\n", stats.file_length);
	logfile("Flashing file to NAND successful! New file is %u bytes.\r\n", stats.file_length);
	
	ISFS_Close(nandfile);*/
	
	return 0;
}

bool dumpfolder(char source[1024], char destination[1024])
{
	//logfile("\r\n[DUMPFOLDER] Source : '%s' / Destination: '%s'.\r\n", source, destination);
	
	int i;
	u32 tcnt;
	s32 ret;
	char path[1024], path2[1024];
	dirent_t *dir = NULL;
	
	ret = getdir_info(source, &dir, &tcnt);
	if (ret < 0)
	{
		printf("Error reading source directory.\n");
		logfile("Error reading source directory.\r\n");
		if (dir) free(dir);
		return false;
	}
	
	remove(destination);
	
	for (i = 0; i < tcnt; i++) 
	{
		snprintf(path, MAX_CHARACTERS(path), "%s/%s", source, dir[i].name);
		
		if (strncmp(dir[i].name, "title.tmd", 9) != 0)
		{
			logfile("\r\nSource file is '%s'.\r\n", path);
			
			snprintf(path2, MAX_CHARACTERS(path2), "%s/%s", destination, dir[i].name);
			
			if (!create_folders(path2))
			{
				//printf("Error creating folder(s) for '%s'.\n", path2);
				logfile("Error creating folder(s) for '%s'.\r\n", path2);
				return false;
			}
			
			if (dir[i].type == DIRENT_T_FILE) 
			{
				logfile("Destination file is '%s'.\r\n", path2);
				ret = dumpfile(path, path2);
				if (ret < 0)
				{
					printf("Error dumping file from NAND.\n");
					logfile("Error dumping file from NAND.\r\n");
					free(dir);
					return false;
				}
			} else {
				logfile("Destination dir is '%s'.\r\n", path2);
				remove(path2);
				
				if (!dumpfolder(path, path2))
				{
					//remove(path2);
					free(dir);
					return false;
				}
			}
		} else {
			/* Probably a leftover from a previous version of BlueDump, so let's delete it silently... */
			ISFS_Delete(path);
			logfile("title.tmd detected in '%s' automatically deleted.\r\n", source);
		}
	}
	
	free(dir);
	return true;
}

bool writefolder(char *source, char *destination)
{
	//logfile("\r\n[WRITEFOLDER] Source : '%s' / Destination: '%s'.\r\n", source, destination);
	
	u32 tcnt;
	s32 ret;
	int i;
	char path[512];
	char path2[512];
	
	dirent_t *dir = NULL;
	ret = getdir_device(source, &dir, &tcnt);
	if (ret < 0)
	{
		printf("Error reading source directory.\n");
		logfile("Error reading source directory.\r\n");
		if (dir) free(dir);
		return false;
	}
	
	ret = ISFS_Delete(destination);
	logfile("ISFS_Delete('%s') returned %d.\r\n", destination, ret);
	ret = ISFS_CreateDir(destination, 0, 3, 3, 3);
	logfile("ISFS_CreateDir('%s', 0, 3, 3, 3) returned %d.\r\n", destination, ret);
	
	for (i = 0; i < tcnt; i++) 
	{
		/* We'll flash the title.tmd file separately in install_savedata() */
		if (strncmp(dir[i].name, "title.tmd", 9) != 0)
		{
			snprintf(path, MAX_CHARACTERS(path), "%s/%s", source, dir[i].name);
			logfile("Source file is '%s'.\r\n", path);
			
			snprintf(path2, MAX_CHARACTERS(path2), "%s/%s", destination, dir[i].name);
			
			if (dir[i].type == DIRENT_T_FILE)
			{
				logfile("Destination file is '%s'.\r\n", path2);
				ret = flash(path, path2);
				if (ret < 0)
				{
					printf("Error flashing file to NAND.\n");
					logfile("Error flashing file to NAND.\r\n");
					free(dir);
					return false;
				}
			} else {
				logfile("Destination dir is '%s'.\r\n", path2);
				
				if (!writefolder(path, path2))
				{
					//ISFS_Delete(path2);
					free(dir);
					return false;
				}
			}
		}
	}
	
	free(dir);
	return true;
}

char *GetASCII(u32 name)
{
	int i;
	u8 temp, j = 0;
	
	for (i = 24; i >= 0; i -= 8)
	{
		temp = (name >> i) & 0xFF;
		if (temp < 0x20 || temp > 0x7E)
		{
			ascii_id[j] = '.';
		} else {
			ascii_id[j] = temp;
		}
		j++;
	}
	
	ascii_id[4] = 0;
	return ascii_id;
}

char *RemoveIllegalCharacters(char *name)
{
	u32 i, len = strlen(name);
	for (i = 0; i < len; i++)
	{
		// libFAT has problems reading and writing filenames with Unicode characters, like "�"
		if (memchr("?[]/\\=+<>:;\",*|^", name[i], sizeof("?[]/\\=+<>:;\",*|^") - 1) || name[i] < 0x20 || name[i] > 0x7E) name[i] = '_';
	}
	return name;
}

void extract_savedata(u64 titleID)
{
	s32 ret;
	char *id = GetASCII(TITLE_LOWER(titleID));
	char isfs_path[ISFS_MAXPATH], dev_path[MAXPATHLEN]; // source, destination
	
	logfile("Extracting title %08x-%08x...\r\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS path is '%s'.\r\n", isfs_path);
	
	if (TITLE_UPPER(titleID) == 0x00010000)
	{
		//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/DISC %s", DEVICE(0), id);
		snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/DISC %s - %s", DEVICE(0), id, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: disc-based game.\r\n");
	} else
	if (TITLE_UPPER(titleID) == 0x00010001)
	{
		/* Workaround for HBC 1.0.7 - 1.1.0*/
		if (TITLE_LOWER(titleID) == 0xAF1BF516)
		{
			//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN AF1BF516", DEVICE(0));
			snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN AF1BF516 - Homebrew Channel", DEVICE(0));
			logfile("Savedata type: The Homebrew Channel (1.0.7 - 1.1.0).\r\n");
		} else {
			//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN %s", DEVICE(0), id);
			snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN %s - %s", DEVICE(0), id, RemoveIllegalCharacters(get_name(titleID, false)));
			logfile("Savedata type: downloaded channel title.\r\n");
		}
	} else
	if (TITLE_UPPER(titleID) == 0x00010004)
	{
		//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHSV %s", DEVICE(0), id);
		snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHSV %s - %s", DEVICE(0), id, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: game that uses channel.\r\n");
	}
	
	logfile("%s path is '%s'.\r\n", DEVICE(1), dev_path);
	
	if (dumpfolder(isfs_path, dev_path))
	{
		/* Dump the title.tmd file */
		snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
		strncat(dev_path, "/title.tmd", 10);
		
		logfile("\r\ntitle.tmd path = %s.\r\n", isfs_path);
		logfile("path_out = %s.\r\n", dev_path);
		
		ret = dumpfile(isfs_path, dev_path);
		if (ret < 0)
		{
			printf("\n\nError dumping title.tmd to %s.\n", DEVICE(1));
			logfile("\r\nError dumping title.tmd to %s.\r\n", DEVICE(1));
		} else {
			printf("\n\nDumping folder complete.\n");
			logfile("\r\nDumping folder complete.\r\n");
		}
	}
}	

void install_savedata(u64 titleID)
{
	s32 ret;
	bool found = false;
	char *id = GetASCII(TITLE_LOWER(titleID));
	char dev_path[MAXPATHLEN], isfs_path[ISFS_MAXPATH]; // source, destination
	
	logfile("Installing title %08x-%08x...\r\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS path is '%s'.\r\n", isfs_path);
	
	snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata", DEVICE(0));
	
	/* Search savedata directory on external storage */
	u32 i, tcnt;
	dirent_t *dir = NULL;
	ret = getdir_device(dev_path, &dir, &tcnt);
	if (ret < 0)
	{
		printf("Error reading savedata directory.\n");
		logfile("Error reading savedata directory.\r\n");
		if (dir) free(dir);
		return;
	}
	
	for (i = 0; i < tcnt; i++)
	{
		/* Workaround for HBC 1.0.7 - 1.1.0 */
		if (((TITLE_LOWER(titleID) == 0xAF1BF516) && (strncmp(dir[i].name + 5, "AF1BF516", 8) == 0)) || (strncmp(dir[i].name + 5, id, 4) == 0))
		{
			found = true;
			break;
		}
	}
	
	free(dir);
	
	if (!found)
	{
		printf("Couldn't find the savedata on the %s!\nPlease extract the savedata first.\n", (isSD ? "SD card" : "USB storage"));
		logfile("\r\nCouldn't find the savedata on the %s!\r\n", (isSD ? "SD card" : "USB storage"));
		sleep(3);
		return;
	} else {
		logfile("Savedata found: '%s'.\r\n", dir[i].name);
		snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s/%s", dev_path, dir[i].name);
		logfile("%s path is '%s'.\r\n", DEVICE(1), dev_path);
	}
	
	if (writefolder(dev_path, isfs_path))
	{
		/* Flash the title.tmd file */
		snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
		strncat(dev_path, "/title.tmd", 10);
		
		logfile("\r\ntitle.tmd path = %s.\r\n", dev_path);
		logfile("path_out = %s.\r\n", isfs_path);
		
		ret = flash(dev_path, isfs_path);
		if (ret < 0)
		{
			printf("\n\nError flashing title.tmd to NAND.\n");
			logfile("Error flashing title.tmd to NAND.\r\n");
		} else {
			printf("\n\nFlashing to NAND complete.\n");
			logfile("\r\nFlashing to NAND complete.\r\n");
		}
	}
}	

/* Info taken from Wiibrew */
char *GetSysMenuVersion(u16 version)
{
	switch(version)
	{
		case 33:
			return "v1.0";
		case 97:
			return "v2.0U";
		case 128:
			return "v2.0J";
		case 130:
			return "v2.0E";
		case 162:
			return "v2.1E";
		case 192:
			return "v2.2J";
		case 193:
			return "v2.2U";
		case 194:
			return "v2.2E";
		case 224:
			return "v3.0J";
		case 225:
			return "v3.0U";
		case 226:
			return "v3.0E";
		case 256:
			return "v3.1J";
		case 257:
			return "v3.1U";
		case 258:
			return "v3.1E";
		case 288:
			return "v3.2J";
		case 289:
			return "v3.2U";
		case 290:
			return "v3.2E";
		case 326:
			return "v3.3K";
		case 352:
			return "v3.3J";
		case 353:
			return "v3.3U";
		case 354:
			return "v3.3E";
		case 384:
			return "v3.4J";
		case 385:
			return "v3.4U";
		case 386:
			return "v3.4E";
		case 390:
			return "v3.5K";
		case 416:
			return "v4.0J";
		case 417:
			return "v4.0U";
		case 418:
			return "v4.0E";
		case 448:
			return "v4.1J";
		case 449:
			return "v4.1U";
		case 450:
			return "v4.1E";
		case 454:
			return "v4.1K";
		case 480:
			return "v4.2J";
		case 481:
			return "v4.2U";
		case 482:
			return "v4.2E";
		case 486:
			return "v4.2K";
		case 512:
		case 544:
			if (vwii)
			{
				return "v4.3J (vWii)";
			} else {
				return "v4.3J";
			}
		case 513:
		case 545:
			if (vwii)
			{
				return "v4.3U (vWii)";
			} else {
				return "v4.3U";
			}
		case 514:
		case 546:
			if (vwii)
			{
				return "v4.3E (vWii)";
			} else {
				return "v4.3E";
			}
		case 518:
			return "v4.3K";
		default:
			return "(Unknown Version)";
	}
}

void browser(char cpath[ISFS_MAXPATH + 1], dirent_t* ent, int cline, int lcnt)
{
	int i;
	resetscreen();
	printheadline();
	
	//logfile("\r\n\r\nBROWSER: Using Wii NAND. Inserted device: %s.\r\nPath: %s\r\n", (isSD ? "SD Card" : "USB Storage"), cpath);
	
	printf("[1/Y] Dump options  [A] Confirm / Enter directory  [2/X] Change view mode\n");
	printf("[B] Cancel / Return to parent directory  [-/L] Device menu\n");
	printf("[+/R] Switch to content.bin conversion [HOME/Start] Exit\n\n");
	
	printf("Current device: %s. Path: %s\n\n", DEVICE(1), cpath);
	
	if (lcnt == 0 || ent == NULL)
	{
		printf("No files/directories found!");
		printf("\nPress B to go back to the previous directory.");
	} else {
		for(i = (cline / 14)*14; i < lcnt && i < (cline / 14)*14+14; i++)
		{
			if ((strncmp(cpath, "/title", 6) == 0 && strlen(cpath) == 6) || ent[i].function == TYPE_IOS)
			{
				printf("%s %s - %s\n", (i == cline ? ARROW : "  "), ent[i].name, ent[i].titlename);
			} else
			if (ent[i].function == TYPE_OTHER)
			{
				printf("%s %-12s - %s\n", (i == cline ? ARROW : "  "), ent[i].name, ent[i].titlename);
			} else {
				printf("%s %s - %s\n", (i == cline ? ARROW : "  "), (ascii ? GetASCII(strtoll(ent[i].name, NULL, 16)) : ent[i].name), ent[i].titlename);
			}
		}
	}
	
	fflush(stdout);
}

void make_header(void)
{
	wadHeader *now = allocate_memory(sizeof(wadHeader));
	if (now == NULL) 
	{
		//printf("Error allocating memory for wadheader.\n");
		logfile("Error allocating memory for wadheader.\r\n");
		goodbye();
	}
	
	now->header_len = 0x20;

	now->type = 0x4973;

	now->padding = 0;

	now->certs_len = 0;
	
	now->crl_len = 0;
	
	now->tik_len = 0;
	
	now->tmd_len = 0;
	
	now->data_len = 0;
	
	now->footer_len = 0;
	
	header = now;
}	

s32 get_title_key(signed_blob *s_tik, u8 *key)
{
	static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);

	const tik *p_tik = (tik *)SIGNATURE_PAYLOAD(s_tik);
	u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
	memcpy(keyout, enc_key, sizeof(keyout));
	logfile("\r\nEncrypted Title Key = ");
	hex_key_dump(keyout, sizeof(keyout));
	
	memset(iv, 0, sizeof(iv));
	memcpy(iv, &p_tik->titleid, sizeof(p_tik->titleid));
	
	if (aes_128_cbc_decrypt(commonkey, iv, keyout, sizeof(keyout)) < 0)
	{
		printf("Error decrypting Title Key.");
		logfile("Error decrypting Title Key.");
		return -1;
	}
	
	memcpy(key, keyout, sizeof(keyout));
	logfile("\r\nDecrypted Title Key = ");
	hex_key_dump(keyout, sizeof(keyout));
	logfile("\r\n");
	
	return 0;
}

s32 Wad_Dump(u64 id, char *path)
{
	make_header();
	
	logfile("Path for dump = %s.\r\n", path);
	logfile("Started WAD Packing...\r\nPacking Title %08x-%08x.\r\n", TITLE_UPPER(id), TITLE_LOWER(id));

	signed_blob *p_tik = NULL;
	signed_blob *p_tmd = NULL;
	
	tmd *tmd_data = NULL;
	u8 key[16];
	
	s32 ret;
	u32 cnt;
	
	if (!create_folders(path))
	{
		printf("\nError creating folder(s) for '%s'.\nIs your storage device write protected?\n", path);
		logfile("Error creating folder(s) for '%s'.\r\n", path);
		return -1;
	}

	FILE *wadout = fopen(path, "wb+");
	if (!wadout)
	{
		printf("\nError opening '%s' for writing.\nIs your storage device write protected?\n", path);
		logfile("Error opening '%s' for writing.\r\n", path);
		free(header);
		return -1;
	}
	
	/* Reserve space for the header */
	u8 *padding_table = allocate_memory(64);
	if (padding_table == NULL)
	{
		//printf("Error allocating memory for padding_table.\n");
		logfile("Error allocating memory for padding_table.\r\n");
		free(header);
		fclose(wadout);
		remove(path);
		goodbye();
	}
	memset(padding_table, 0, 64);
	fwrite(padding_table, 64, 1, wadout);
	free(padding_table);
	
	/* Get Certs */
	printf("Reading Certs... ");
	logfile("Reading Certs... ");
	GetCerts(wadout);
	printf("done.\n");
	logfile("done.\r\n");
	
	/* Get Ticket */
	printf("Reading Ticket... ");
	logfile("Reading Ticket... ");
	ret = GetTicket(wadout, id, &p_tik);
	if (ret < 0)
	{
		free(header);
		fclose(wadout);
		remove(path);
		return -1;
	}
	printf("OK.\n");
	logfile("OK.\r\n");
	
	/* Get TMD */
	printf("Reading TMD... ");
	logfile("Reading TMD... ");
	ret = GetTMD(wadout, id, &p_tmd);
	if (ret < 0)
	{
		free(header);
		free(p_tik);
		fclose(wadout);
		remove(path);
		return -1;
	}
	printf("OK.\n");
	logfile("OK.\r\n");
	
	/* Get Title Key */
	printf("Decrypting AES Title Key... ");
	logfile("Decrypting AES Title Key... ");
	ret = get_title_key(p_tik, (u8 *)key);
	free(p_tik);
	
	if (ret < 0)
	{
		free(header);
		free(p_tmd);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	printf("done.\n");
	logfile("done.\r\n");
	
	char footer_path[ISFS_MAXPATH];
	tmd_data = (tmd *)SIGNATURE_PAYLOAD(p_tmd);
	
	/* We'll need this to dump DLCs with missing content */
	bool rewrite = false;
	
	u8 *tmdmod = allocate_memory(header->tmd_len);
	memcpy(tmdmod, p_tmd, header->tmd_len);
	forge((signed_blob*)tmdmod, true, false);
	
	u32 tmdmodsize = header->tmd_len;
	u16 real_cnt_num = tmd_data->num_contents;
	
	for (cnt = 0; cnt < tmd_data->num_contents; cnt++)
	{
		printf("Processing content #%u... ", cnt);
		logfile("Processing content #%u... ", cnt);
		tmd_content *content = &tmd_data->contents[cnt];
		
		if (cnt == 0) snprintf(footer_path, MAX_CHARACTERS(footer_path), "/title/%08x/%08x/content/%08x.app", TITLE_UPPER(id), TITLE_LOWER(id), content->cid);
		
		logfile("Content type 0x%04x... ", content->type);
		switch(content->type)
		{
			case 0x0001: // Normal
			case 0x4001: // DLC
				ret = GetContent(wadout, id, content->cid, (u8*)key, content->index, (u32)content->size, content->hash);
				if (content->type == 0x4001 && ret == -106)
				{
					ret = 0; // Nothing happened here, boy.
					if (!rewrite) rewrite = true;
					
					printf("Skipping DLC content (not available).\n");
					
					/* Reduce the number of contents (0x1DE @ TMD) */
					real_cnt_num--;
					memcpy(&(tmdmod[0x1DE]), &real_cnt_num, 2);
					
					/* Delete the info struct for the missing content file and pad again to a 64-byte boundary*/
					int i;
					for (i = 0; i < (real_cnt_num + 1); i++)
					{
						u32 cntid;
						memcpy(&cntid, &(tmdmod[0x1E4 + (36 * i)]), 4);
						
						if (cntid == content->cid)
						{
							logfile("Found content %08x @ 0x%08x in tmdmod. ", content->cid, 0x1E4 + (36 * i));
							
							if (tmdmodsize > (0x1E4 + (36 * (i + 1))))
							{
								memmove(&(tmdmod[0x1E4 + (36 * i)]), &(tmdmod[0x1E4 + (36 * (i + 1))]), 36 * (real_cnt_num - i));
							}
							
							tmdmodsize -= 36;
							pad_data(tmdmod, tmdmodsize, false);
							logfile("New tmdmodsize: %d bytes.\r\n", tmdmodsize);
							
							break;
						}
					}
					
					/* We'll write the modified TMD and move the data around in the output file after the dump process is done */
				}
				
				break;
			case 0x8001: // Shared
				ret = GetSharedContent(wadout, (u8*)key, content->index, content->hash, cm, content_map_items);
				break;
			default:
				printf("Unknown content type. Aborting mission...\n");
				logfile("Unknown content type. Aborting mission...\r\n");
				free(header);
				free(p_tmd);
				fclose(wadout);
				remove(path);
				goodbye();
		}
		
		fflush(stdout);
		
		if (ret < 0) break;
	}
	
	free(p_tmd);
	
	if (ret < 0)
	{
		printf("\nError reading content!\n");
		logfile("Error reading content! (ret = %d)", ret);
		free(header);
		free(tmdmod);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	/* Add unencrypted footer */
	printf("Adding footer... ");
	logfile("Adding footer... ");
	
	u8 *footer_buf;
	u32 footer_size;
	ret = read_isfs(footer_path, &footer_buf, &footer_size);
	if (ret < 0)
	{
		printf("Error getting footer!\n");
		logfile("Error getting footer!\r\n");
		free(header);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	header->footer_len = footer_size;
	if ((footer_size % 64) != 0) footer_size = pad_data(footer_buf, footer_size, false);
	fwrite(footer_buf, footer_size, 1, wadout);
	free(footer_buf);
	
	printf("done.\n");
	logfile("done.\r\n");
	
	/* Rewrite the whole output file if there were any missing DLC contents */
	if (rewrite)
	{
		printf("Rearranging output file, please wait... ");
		logfile("Rearranging output file...\r\n");
		
		u32 size = ftell(wadout);
		logfile("Current WAD size: %d bytes.\r\n", size);
		
		fseek(wadout, 0xA40 + round64(header->tik_len) + round64(header->tmd_len), SEEK_SET);
		u32 tocopy = ftell(wadout);
		size -= tocopy;
		
		fseek(wadout, 0xA40 + round64(header->tik_len), SEEK_SET);
		fwrite(tmdmod, round64(tmdmodsize), 1, wadout);
		u32 towrite = ftell(wadout);
		printf("Wrote modified TMD @ 0x%08x... ", towrite - round64(tmdmodsize));
		
		logfile("tmdmodsize = %d bytes / size = %d bytes / tocopy = 0x%08x / towrite = 0x%08x\r\n", tmdmodsize, size, tocopy, towrite);
		
		u32 blocksize = SD_BLOCKSIZE;
		u8 *tempbuf = allocate_memory(blocksize);
		
		while (size > 0)
		{
			if (blocksize > size) blocksize = size;
			
			fseek(wadout, tocopy, SEEK_SET);
			fread(tempbuf, blocksize, 1, wadout);
			tocopy = ftell(wadout);
			
			fseek(wadout, towrite, SEEK_SET);
			fwrite(tempbuf, blocksize, 1, wadout);
			towrite = ftell(wadout);
			
			size -= blocksize;
		}
		
		free(tempbuf);
		
		/* Adjust TMD size in header */
		header->tmd_len = tmdmodsize;
		
		ftruncate(fileno(wadout), towrite);
		logfile("New size: %d bytes.\r\n", towrite);
		printf("done.\n");
	}
	
	free(tmdmod);
	
	/* Add WAD header */
	printf("Writing header info... ");
	logfile("Writing header info... ");
	rewind(wadout);
	fwrite((u8 *)header, 0x20, 1, wadout);
	printf("done.\n");
	logfile("done.\r\nHeader hexdump:\r\n");
	hexdump_log(header, 0x20);
	
	free(header);
	fclose(wadout);
	
	return 0;
}

s32 Content_bin_Dump(FILE *cnt_bin, char* path)
{
	make_header();
	
	logfile("Path for dump = %s.\r\n", path);
	logfile("Started WAD Packing...\r\n");
	
	signed_blob *p_tik = NULL;
	signed_blob *p_tmd = NULL;
	
	tmd *tmd_data = NULL;
	
	u8 key[16];
	
	s32 ret;
	u64 titleID;
	u32 i, cnt, part_C_cid, tmd_size = 0, footer_offset = 0;
	
	if (!create_folders(path))
	{
		printf("\nError creating folder(s) for '%s'.\nIs your storage device write protected?\n", path);
		logfile("Error creating folder(s) for '%s'.\r\n", path);
		return -1;
	}
	
	fseek(cnt_bin, 0, SEEK_END);
	u32 cnt_size = ftell(cnt_bin);
	rewind(cnt_bin);
	
	FILE *wadout = fopen(path, "wb+");
	if (!wadout)
	{
		printf("\nError opening '%s' for writing.\nIs your storage device write protected?\n", path);
		logfile("Error opening '%s' for writing.\r\n", path);
		free(header);
		return -1;
	}
	
	/* Reserve space for the header */
	u8 *padding_table = allocate_memory(64);
	if (padding_table == NULL)
	{
		//printf("\nError allocating memory for padding_table.\n");
		logfile("Error allocating memory for padding_table.\r\n");
		free(header);
		fclose(cnt_bin);
		fclose(wadout);
		remove(path);
		goodbye();
	}
	memset(padding_table, 0, 64);
	fwrite(padding_table, 64, 1, wadout);
	free(padding_table);
	
	/* Get Certs */
	printf("Reading Certs... ");
	logfile("Reading Certs... ");
	GetCerts(wadout);
	printf("done.\n");
	logfile("done.\r\n");
	
	/* Access OTP to get both the PRNG Key and the Console ID */
	if (console_id == 0)
	{
		printf("Mounting OTP memory... ");
		logfile("Mounting OTP memory... ");
		ret = Get_OTP_data();
		if (ret < 0)
		{
			free(header);
			fclose(cnt_bin);
			fclose(wadout);
			remove(path);
			goodbye();
		} else {
			printf("done.\n");
			logfile("done.\r\n");
		}
	}
	
	/* Search for the "Bk" magic word, which serves as an identifier for part C */
	/* We need to access this part because it contains both TMD size and console ID */
	/* We'll use the console ID to verify if the content.bin file was generated in this Wii */
	printf("Searching for part C (\"Bk\" header)... ");
	logfile("Searching for part C (\"Bk\" header)... ");
	
	u8 *temp = allocate_memory(0x14);
	if (temp == NULL)
	{
		//printf("\nError allocating memory for temp.");
		logfile("\r\nError allocating memory for temp.");
		free(header);
		fclose(cnt_bin);
		fclose(wadout);
		remove(path);
		goodbye();
	}
	
	fseek(cnt_bin, 0x644, SEEK_SET);
	
	bool found = false;
	u8 bk[4] = { 0x42, 0x6b, 0x00, 0x01 };
	
	for (i = 0; i < (cnt_size - 0x644); i += 0x20)
	{
		/* "Bk" header */
		fread(temp, 0x14, 1, cnt_bin);
		if (memcmp(temp, bk, 4) == 0)
		{
			found = true;
			
			logfile("\"Bk\" header found @ 0x%08x... ", ftell(cnt_bin) - 0x14);
			
			/* Console ID verification */
			memcpy(&part_C_cid, &(temp[0x04]), 4);
			if (part_C_cid != console_id)
			{
				printf("\nError: Console ID mismatch. This content.bin file was not generated by this Wii!");
				logfile("\r\nError: Console ID mismatch. This content.bin file was not generated by this Wii!");
				free(temp);
				free(header);
				fclose(wadout);
				remove(path);
				return -1;
			}
			
			/* Store TMD size */
			memcpy(&tmd_size, &(temp[0x10]), 4);
			header->tmd_len = tmd_size;
			logfile("TMD Size = %u... ", tmd_size);
			
			/* Prepare file stream position for TMD access */
			fseek(cnt_bin, 0x68, SEEK_CUR);
			
			break;
		}
		
		fseek(cnt_bin, 0x0C, SEEK_CUR);
	}
	
	free(temp);
	
	if (!found)
	{
		printf("\nError: Couldn't identify \"Bk\" header in content.bin file.\n");
		logfile("\r\nError: Couldn't identify \"Bk\" header in content.bin file.\r\n");
		free(header);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	printf("done.\n");
	logfile("done.\r\n");
	
	/* Get TMD */
	printf("Reading TMD... ");
	logfile("Reading TMD... ");
	u8 *tmd_buf = allocate_memory(tmd_size);
	if (tmd_buf == NULL)
	{
		printf("Error allocating memory for p_tmd.\n");
		logfile("Error allocating memory for p_tmd.\r\n");
		free(header);
		fclose(cnt_bin);
		fclose(wadout);
		remove(path);
		goodbye();
	}
	
	fread(tmd_buf, tmd_size, 1, cnt_bin);
	
	/* Store the 64-bit TitleID (we need it for the GetTicket() function) */
	memcpy(&titleID, &(tmd_buf[0x18C]), 8);
	logfile("TitleID: %08x-%08x... ", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	
	if ((tmd_size % 64) != 0)
	{
		/* Prepare file stream position for content access */
		fseek(cnt_bin, round64(tmd_size) - tmd_size, SEEK_CUR);
		tmd_size = pad_data(tmd_buf, tmd_size, false);
		logfile("Padded TMD size = %u... ", tmd_size);
	}
	
	footer_offset = ftell(cnt_bin);
	
	if (ftmd) forge((signed_blob *)tmd_buf, true, true);
	p_tmd = (signed_blob *)tmd_buf;
	
	printf("OK.\n");
	logfile("OK.\r\n");
	
	/* Get Ticket */
	printf("Reading Ticket... ");
	logfile("Reading Ticket... ");
	ret = GetTicket(wadout, titleID, &p_tik);
	if (ret < 0)
	{
		free(header);
		free(tmd_buf);
		fclose(wadout);
		remove(path);
		return -1;
	}
	printf("OK.\n");
	logfile("OK.\r\n");
	
	/* Get Title Key */
	printf("Decrypting AES Title Key... ");
	logfile("Decrypting AES Title Key... ");
	ret = get_title_key(p_tik, (u8 *)key);
	free(p_tik);
	
	if (ret < 0)
	{
		free(header);
		free(tmd_buf);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	printf("done.\n");
	logfile("done.\r\n");
	
	/* Now we can write the TMD data */
	fwrite(p_tmd, tmd_size, 1, wadout);
	
	static u8 footer_iv[16];
	u32 footer_size = 0;
	
	tmd_data = (tmd *)SIGNATURE_PAYLOAD(p_tmd);
	for (cnt = 0; cnt < tmd_data->num_contents; cnt++)
	{
		printf("Processing content #%u... ", cnt);
		logfile("Processing content #%u... ", cnt);
		tmd_content *content = &tmd_data->contents[cnt];
		
		if (cnt == 0)
		{
			/* Footer info */
			memset(footer_iv, 0, 16);
			memcpy(footer_iv, &content->index, 2);
			header->footer_len = (u32)content->size;
			footer_size = round64(header->footer_len);
		}
		
		logfile("Content type 0x%04x... ", content->type);
		switch (content->type)
		{
			case 0x0001: // Normal
			case 0x4001: // DLC, I'm not sure if this type of content gets included or not, but let's stay on the safe side
				printf("Adding regular content %08x... ", content->cid);
				ret = GetContentFromCntBin(cnt_bin, wadout, content->index, (u32)content->size, (u8*)key, content->hash);
				break;
			case 0x8001: // Shared, they don't get included in the content.bin file
				ret = GetSharedContent(wadout, (u8*)key, content->index, content->hash, cm, content_map_items);
				break;
			default:
				printf("Unknown content type. Aborting mission...\n");
				logfile("Unknown content type. Aborting mission...\r\n");
				free(header);
				free(p_tmd);
				fclose(cnt_bin);
				fclose(wadout);
				remove(path);
				goodbye();
		}
		
		fflush(stdout);
		
		if (ret < 0) break;
	}
	
	free(p_tmd);
	rewind(cnt_bin);
	
	if (ret < 0)
	{
		printf("\nError reading content!\n");
		logfile("Error reading content!");
		free(header);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	/* Add unencrypted footer */
	printf("Adding footer... ");
	logfile("Adding footer... ");
	
	u8 *footer_buf = allocate_memory(footer_size);
	if (footer_buf == NULL)
	{
		printf("Error allocating memory for footer_buf.\n");
		logfile("Error allocating memory for footer_buf.\r\n");
		free(header);
		fclose(cnt_bin);
		fclose(wadout);
		remove(path);
		goodbye();
	}
	
	logfile("Footer offset: 0x%08x... ", footer_offset);
	
	fseek(cnt_bin, footer_offset, SEEK_SET);
	fread(footer_buf, footer_size, 1, cnt_bin);
	
	if (aes_128_cbc_decrypt(prng_key, footer_iv, footer_buf, footer_size) < 0)
	{
		printf("Error decrypting footer data.\n");
		logfile("Error decrypting footer data.\r\n");
		free(header);
		free(footer_buf);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	if ((header->footer_len % 64) != 0) pad_data(footer_buf, header->footer_len, false);
	
	fwrite(footer_buf, footer_size, 1, wadout);
	free(footer_buf);
	
	printf("done.\n");
	logfile("done.\r\n");
	
	/* Add WAD header */
	printf("Writing header info... ");
	logfile("Writing header info... ");
	rewind(wadout);
	fwrite((u8 *)header, 0x20, 1, wadout);
	printf("done.\n");
	logfile("done.\r\nHeader hexdump:\r\n");
	hexdump_log(header, 0x20);
	
	free(header);
	fclose(wadout);
	
	return 0;
}

u64 copy_id(char *path)
{
	//logfile("COPY_ID: path = %s.\r\n", path);
	char low_out[10], high_out[10];
	
	snprintf(high_out, 9, path+7);
	snprintf(low_out, 9, path+16);

	u64 titleID = TITLE_ID(strtol(high_out, NULL, 16), strtol(low_out, NULL, 16));
	//logfile("Generated COPY_ID was '%08x-%08x'.\r\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	
	return titleID;
}

void YesNoPrompt(char *prompt, char *name, bool *option)
{
	u32 pressed;
	
	printf("\n\n%s", prompt);
	printf("\n[A] Yes    [B] No\n");
	
	while(true)
	{
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		if (pressed & WPAD_BUTTON_A)
		{
			*option = true;
			logfile("%s set to true.\r\n", name);
			break;
		}
		
		if (pressed & WPAD_BUTTON_B)
		{
			*option = false;
			logfile("%s set to false.\r\n", name);
			break;
		}
	}
}

void select_forge(int type)
{
	YesNoPrompt("Do you want to fakesign the ticket?", "ftik", &ftik);
	YesNoPrompt("Do you want to fakesign the TMD?", "ftmd", &ftmd);
	
	/* WAD region change prompt */
	/* We cannot change the WAD region if the TMD isn't fakesigned */
	/* Also, avoid showing this prompt if a system title was selected */
	if (ftmd && type != TYPE_IOS && type != TYPE_SYSTITLE && type != TYPE_HIDDEN)
	{
		YesNoPrompt("Do you want to change the output WAD region?", "change_region", &change_region);
		if (change_region)
		{
			u32 pressed;
			u8 selection = 0;
			char *region_str[4] = { "Japanese >", "< American >" , "< European >", "< **FREE**" };
			printf("\n");
			
			while(true)
			{
				Con_ClearLine();
				
				printf("Select the new region: ");
				
				set_highlight(true);
				printf(region_str[selection]);
				set_highlight(false);
				
				pressed = DetectInput(DI_BUTTONS_DOWN);
				
				if (pressed & WPAD_BUTTON_LEFT)
				{	
					if (selection > 0) selection--;
				}
				
				if (pressed & WPAD_BUTTON_RIGHT)
				{	
					if (selection < 3) selection++;
				}
				
				if (pressed & WPAD_BUTTON_A) break;
			}
			
			region = selection;
		}
	}
}

void dump_menu(char *cpath, int cline, dirent_t *ent)
{
	u32 pressed;
	
	int selection = 0;
	char *options[3] = { "Backup Savedata >", "< Restore Savedata >" , "< Backup to WAD"};
	
	while(true)
	{
		resetscreen();
		printheadline();
		
		printf("Select what to do: ");
		
		set_highlight(true);
		printf(options[selection]);
		set_highlight(false);
		
		printf("\n\nPress B to return to the browser.");
		
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		if (pressed & WPAD_BUTTON_LEFT)
		{	
			if (selection > 0) selection--;
		}
		
		if (pressed & WPAD_BUTTON_RIGHT)
		{	
			if (selection < 2) selection++;
		}
		
		if (pressed & WPAD_BUTTON_B) return;
		if (pressed & WPAD_BUTTON_A) break;
	}
	
	char some[ISFS_MAXPATH + 1];
	snprintf(some, MAX_CHARACTERS(some), "%s/%s", cpath, ent[cline].name);
	
	logfile("\r\n[DUMP_MENU] Selected item: %s.\r\n", some);
	u64 titleID = copy_id(some);
	u32 low = TITLE_LOWER(titleID);
	
	switch(selection)
	{
		case 0: // Backup savedata
			if ((ent[cline].function == TYPE_SAVEDATA && low != 0x48415a41) || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
			{
				printf("\n\nBacking up savedata...\n\n");
				logfile("Backing up savedata...\r\n");
				extract_savedata(titleID);
			} else {
				printf("\n\nThe title you chose has no savedata!\n");
				printf("Use the WAD function for this.");
			}
			break;
		case 1: // Restore savedata
			if ((ent[cline].function == TYPE_SAVEDATA && low != 0x48415a41) || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
			{
				printf("\n\nRestoring savedata...\n\n");
				logfile("Restoring savedata...\r\n");
				install_savedata(titleID);
			} else {
				printf("\n\nThe title you chose has no savedata!\n");
				printf("Use the WAD function for this.");
			}
			break;	
		case 2: // Backup to WAD
			/* Workaround for HAZA (00010000-48415a41) */
			/* This title is responsible for changing the Photo Channel v1.0 placeholder in the System Menu to v1.1 */
			if ((ent[cline].function == TYPE_SAVEDATA && low != 0x48415a41) || ent[cline].function == TYPE_OTHER)
			{
				printf("\n\nThis is not a title! Use the savedata functions for this.\n");
			} else {
				char dump_path[100];
				
				logfile("\r\nCreating WAD...\r\n");
				
				select_forge(ent[cline].function);
				
				resetscreen();
				printheadline();
				printf("Creating WAD...\n");
				
				if (ent[cline].function == TYPE_SAVEDATA || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_SYSTITLE || ent[cline].function == TYPE_GAMECHAN || ent[cline].function == TYPE_DLC)
				{
					/* Workaround for HBC 1.0.7 - 1.1.0 */
					if (low != 0xAF1BF516)
					{
						snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/%s v%u - %s", DEVICE(0), RemoveIllegalCharacters(get_name(titleID, false)), get_version(titleID), GetASCII(low));
					} else {
						snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/Homebrew Channel - AF1BF516", DEVICE(0));
					}
				} else {
					if ((strncmp(ent[cline].titlename, "Unknown Hidden Channel", 22) == 0) || (strncmp(ent[cline].titlename, "Channel/Title deleted from Wii Menu? (couldn't get info)", 56) == 0))
					{
						snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/%08x-%s v%u", DEVICE(0), TITLE_UPPER(titleID), ent[cline].name, get_version(titleID));
					} else {
						snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/%s", DEVICE(0), ent[cline].titlename);
					}
				}
				
				if (ftik && ftmd)
				{
					strncat(dump_path, " (ftmd+ftik).wad", 16);
				} else
				if (!ftik && ftmd)
				{
					strncat(dump_path, " (ftmd).wad", 11);
				} else
				if (ftik && !ftmd)
				{
					strncat(dump_path, " (ftik).wad", 11);
				} else {
					strncat(dump_path, ".wad", 4);
				}
				
				s32 ret = Wad_Dump(titleID, dump_path);
				if (ret < 0)
				{
					printf("\nError dumping title to WAD file!");
				} else {
					logfile("WAD dump complete!\r\n");
					printf("WAD dump complete! Output file:\n\n\t%s", dump_path);
				}
			}
			break;
		default:
			break;
	}
	
	fflush(stdout);
	usleep(3000000);
}

void sd_browser_ent_info(dirent_t* ent, int cline, int lcnt)
{
	int i;
	resetscreen();
	printheadline();
	
	//logfile("\r\n\r\nSD_BROWSER: Using SD card. Inserted device: %s.\r\nPath: % s\r\n", (isSD ? "SD Card" : "USB Storage"), SD_ROOT_DIR);
	
	printf("[A] Convert selected title's content.bin file to WAD  [HOME/Start] Exit\n");
	printf("[+/R] Return to the main browser screen  [-/L] Device menu\n\n");
	
	printf("Current device: %s. Path: %s\n\n", DEVICE(1), SD_ROOT_DIR);
	
	for (i = (cline / 15)*15; i < lcnt && i < (cline / 15)*15+15; i++)
	{
		printf("%s %-12s - %s\n", (i == cline ? ARROW : "  "), ent[i].name, ent[i].titlename);
	}
	
	fflush(stdout);
}

void dump_menu_sd(char *cnt_path)
{
	logfile("\r\nCreating WAD...\r\n");
	
	resetscreen();
	printheadline();
	
	select_forge(TYPE_OTHER);
	
	resetscreen();
	printheadline();
	printf("Creating WAD...\n");
	
	FILE *cnt_bin = fopen(cnt_path, "rb");
	if (!cnt_bin)
	{
		printf("\nError opening '%s' for reading.\n", cnt_path);
		logfile("\r\nError opening '%s' for reading.\r\n", cnt_path);
		sleep(3);
		return;
	}
	
	char dump_path[100];
	snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/%s - %.4s (content.bin)", DEVICE(0), RemoveIllegalCharacters(read_cntbin_name(cnt_bin, false)), cnt_path+22);
	rewind(cnt_bin);
	
	if (ftik && ftmd)
	{
		strncat(dump_path, " (ftmd+ftik).wad", 16);
	} else
	if (!ftik && ftmd)
	{
		strncat(dump_path, " (ftmd).wad", 11);
	} else
	if (ftik && !ftmd)
	{
		strncat(dump_path, " (ftik).wad", 11);
	} else {
		strncat(dump_path, ".wad", 4);
	}
	
	s32 ret = Content_bin_Dump(cnt_bin, dump_path);
	if (ret < 0)
	{
		printf("\nError dumping title to WAD file!");
	} else {
		logfile("WAD dump complete!\r\n");
		printf("WAD dump complete! Output file:\n\n\t%s", dump_path);
	}
	
	fclose(cnt_bin);
	fflush(stdout);
	usleep(3000000);
}

void sd_browser()
{
	s32 ret;
	char tmp[64];
	dirent_t* ent = NULL;
	u32 i, lcnt = 0, cline = 0;
	
	resetscreen();
	printheadline();
	
	if (!SDmnt)
	{
		printf("Error: SD card is not mounted!");
		sleep(3);
		return;
	}
	
	printf("Reading directory info into memory, please wait...");
	
	ret = getdir_device(SD_ROOT_DIR, &ent, &lcnt);
	if (ret < 0)
	{
		if (ent) free(ent);
		
		switch (ret)
		{
			case -1:
				printf("\n\nError opening '%s'.", SD_ROOT_DIR);
				break;
			case -2:
				printf("\n\nNo files/directories found in '%s'!", SD_ROOT_DIR);
				break;
			default:
				printf("\n\nError allocating memory.");
				break;
		}
		
		usleep(3000000);
		
		return;
	}
	
	FILE *f;
	u32 cntbin_num = 0;
	bool cntbin_exists[lcnt];
	
	/* Create name list - Speeds up directory browsing */
	for (i = 0; i < lcnt; i++)
	{
		if (ent[i].type == DIRENT_T_DIR)
		{
			snprintf(tmp, MAX_CHARACTERS(tmp), "%s/%s/content.bin", SD_ROOT_DIR, ent[i].name);
			f = fopen(tmp, "rb");
			if (f)
			{
				cntbin_num++;
				cntbin_exists[i] = true;
				snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), read_cntbin_name(f, true));
				fclose(f);
			} else {
				cntbin_exists[i] = false;
			}
		} else {
			cntbin_exists[i] = false;
		}
	}
	
	if (cntbin_num == 0)
	{
		free(ent);
		logfile("\r\nError: couldn't find any content.bin file!");
		printf("\n\nError: couldn't find any content.bin file!");
		usleep(3000000);
		return;
	} else
	if (cntbin_num < lcnt)
	{
		/* Skip dir entries without a content.bin file */
		u32 j = 0;
		
		for (i = 0; i < lcnt; i++)
		{
			if ((cntbin_exists[i] == false) && ((lcnt - 1) > i))
			{
				memmove(&(ent[i - j]), &(ent[i - j + 1]), (sizeof(dirent_t) * (lcnt - i - 1)));
				j++;
			}
		}
		
		logfile("lcnt = %u / cntbin_num = %u / j = %u.\r\n", lcnt, cntbin_num, j);
		
		if (realloc(ent, sizeof(dirent_t) * cntbin_num) == NULL)
		{
			logfile("Error reallocating memory block.\r\n");
			printf("\n\nError reallocating memory block.");
			
			free(ent);
			usleep(3000000);
			return;
		} else {
			lcnt = cntbin_num;
		}
	}
	
	u32 pressed;
	sd_browser_ent_info(ent, cline, lcnt);
	
	while (true)
	{
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		/* Navigate up */
		if (pressed & WPAD_BUTTON_UP)
		{			
			if (cline > 0) 
			{
				cline--;
			} else {
				cline = lcnt - 1;
			}
			
			sd_browser_ent_info(ent, cline, lcnt);
		}
		
		/* Navigate down */
		if (pressed & WPAD_BUTTON_DOWN)
		{
			if (cline < (lcnt - 1))
			{
				cline++;
			} else {
				cline = 0;
			}
			
			sd_browser_ent_info(ent, cline, lcnt);
		}
		
		/* Navigate left */
		if (pressed & WPAD_BUTTON_LEFT)
		{
			if (cline > 0)
			{
				if (lcnt <= 4 || cline <= 4)
				{
					cline = 0;
				} else {
					cline -= 4;
				}
				
				sd_browser_ent_info(ent, cline, lcnt);
			}
		}
		
		/* Navigate right */
		if (pressed & WPAD_BUTTON_RIGHT)
		{
			if (cline < (lcnt - 1))
			{
				if (lcnt <= 4 || cline >= (lcnt - 5))
				{
					cline = lcnt - 1;
				} else {
					cline += 4;
				}
				
				sd_browser_ent_info(ent, cline, lcnt);
			}
		}
		
		/* Start conversion to WAD */
		if (pressed & WPAD_BUTTON_A)
		{
			if (ent[cline].type == DIRENT_T_DIR)
			{
				snprintf(tmp, MAX_CHARACTERS(tmp), "%s/%s/content.bin", SD_ROOT_DIR, ent[cline].name);
				dump_menu_sd(tmp);
				sd_browser_ent_info(ent, cline, lcnt);
			}
		}
		
		/* Return to the main browser screen */
		if (pressed & WPAD_BUTTON_PLUS) break;
		
		/* Device Menu */
		if (pressed & WPAD_BUTTON_MINUS)
		{
			/* No device swapping allowed in this case */
			Device_Menu(false);
			sd_browser_ent_info(ent, cline, lcnt);
		}
		
		/* Chicken out */
		if (pressed & WPAD_BUTTON_HOME)
		{
			printf("\nExiting...");
			free(ent);
			goodbye();
		}
	}
	
	free(ent);
}

void create_name_list(char cpath[ISFS_MAXPATH + 1], dirent_t* ent, int lcnt)
{
	if (lcnt == 0) return;
	
	int i;
	for (i = 0; i < lcnt; i++)
	{
		if (strncmp(cpath, "/title", 6) == 0 && strlen(cpath) == 6)
		{
			switch (strtoll(ent[i].name, NULL, 16))
			{
				case 0x00000001:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "System Titles");
					break;
				case 0x00010000:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Disc Savedata");
					break;
				case 0x00010001:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Installed Channel Titles");
					break;
				case 0x00010002:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "System Channel Titles");
					break;
				case 0x00010004:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Games that use Channels (Channel+Save)");
					break;
				case 0x00010005:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Downloadable Game Content (DLC)");
					break;
				case 0x00010008:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Hidden Channels");
					break;
				default:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "*** UNKNOWN ***");
					break;
			}
		} else
		if (ent[i].function == TYPE_IOS)
		{
			switch (strtoll(ent[i].name, NULL, 16))
			{
				case 0x00000000:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Unknown System Title");
					break;
				case 0x00000001:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "BOOT2");
					break;
				case 0x00000002:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "System Menu %s", GetSysMenuVersion(get_version(TITLE_ID(0x00000001, 0x00000002))));
					break;
				case 0x00000100:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "BC v%u", get_version(TITLE_ID(0x00000001, 0x00000100)));
					break;
				case 0x00000101:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "MIOS v%u", get_version(TITLE_ID(0x00000001, 0x00000101)));
					break;
				case 0x00000200:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "BC-NAND v%u", get_version(TITLE_ID(0x00000001, 0x00000200)));
					break;
				case 0x00000201:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "BC-WFS v%u", get_version(TITLE_ID(0x00000001, 0x00000201)));
					break;
				default:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "IOS%u v%u", (u32)strtol(ent[i].name, NULL, 16), get_version(TITLE_ID(0x00000001, strtoll(ent[i].name, NULL, 16))));
					break;
			}
		} else
		if (ent[i].function == TYPE_HIDDEN)
		{
			switch (strtoll(ent[i].name, NULL, 16))
			{
				case 0x48414b45:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "EULA (USA) v%u", get_version(TITLE_ID(0x00010008, 0x48414b45)));
					break;
				case 0x48414b4a:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "EULA (JAP) v%u", get_version(TITLE_ID(0x00010008, 0x48414b4a)));
					break;
				case 0x48414b4b:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "EULA (KOR) v%u", get_version(TITLE_ID(0x00010008, 0x48414b4b)));
					break;
				case 0x48414b50:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "EULA (EUR) v%u", get_version(TITLE_ID(0x00010008, 0x48414b50)));
					break;
				case 0x48414c45:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Region Select (USA) v%u", get_version(TITLE_ID(0x00010008, 0x48414c45)));
					break;
				case 0x48414c4a:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Region Select (JAP) v%u", get_version(TITLE_ID(0x00010008, 0x48414c4a)));
					break;
				case 0x48414c4b:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Region Select (KOR) v%u", get_version(TITLE_ID(0x00010008, 0x48414c4b)));
					break;
				case 0x48414c50:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Region Select (EUR) v%u", get_version(TITLE_ID(0x00010008, 0x48414c50)));
					break;
				case 0x44564458:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "DVDx (pre-4.2 fix)");
					break;
				case 0x44495343:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "DVDx (new version)");
					break;
				default:
					snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Unknown Hidden Channel");
					break;
			}
		} else
		if (ent[i].function == TYPE_SAVEDATA)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), get_name(TITLE_ID(0x00010000, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_TITLE)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), get_name(TITLE_ID(0x00010001, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_SYSTITLE)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), get_name(TITLE_ID(0x00010002, strtoll(ent[i].name, NULL, 16)), false));
		} else
		if (ent[i].function == TYPE_GAMECHAN)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), get_name(TITLE_ID(0x00010004, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_DLC)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), get_name(TITLE_ID(0x00010005, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_OTHER)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), (ent[i].type == DIRENT_T_DIR ? "Directory" : "File"));
		}
	}
}

void yabdm_loop(void)
{
	/* Get Console Language */
	lang = CONF_GetLanguage();
	
	if (__debug)
	{
		reset_log();
		logfile_header();
	}
	
	/* Read the content.map file here to avoid reading it at a later time */
	GetContentMap();
	if (cm == NULL || content_map_size == 0)
	{
		printf("\n\nError loading '/shared1/content.map', size = 0.");
		logfile("\r\nError loading '/shared1/content.map', size = 0.");
		goodbye();
	}
	
	content_map_items = content_map_size/sizeof(map_entry_t);
	
	int i = 0, ret;
	char tmp[ISFS_MAXPATH + 1];
	char cpath[ISFS_MAXPATH + 1];
	dirent_t* ent = NULL;
	u32 pressed, lcnt = 0, cline = 0;
	
	snprintf(cpath, MAX_CHARACTERS(cpath), ROOT_DIR);
	getdir_info(cpath, &ent, &lcnt);
	
	/* Create name list - Speeds up directory browsing */
	create_name_list(cpath, ent, lcnt);
	
	/* Show dir entries */
	browser(cpath, ent, cline, lcnt);
	
	while(true)
	{
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		/* Navigate up */
		if (pressed & WPAD_BUTTON_UP)
		{
			if (cline > 0) 
			{
				cline--;
			} else {
				cline = lcnt - 1;
			}
			
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Navigate down */
		if (pressed & WPAD_BUTTON_DOWN)
		{
			if (cline < (lcnt - 1))
			{
				cline++;
			} else {
				cline = 0;
			}
			
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Navigate left */
		if (pressed & WPAD_BUTTON_LEFT)
		{
			if (cline > 0)
			{
				if (lcnt <= 4 || cline <= 4)
				{
					cline = 0;
				} else {
					cline -= 4;
				}
				
				browser(cpath, ent, cline, lcnt);
			}
		}
		
		/* Navigate right */
		if (pressed & WPAD_BUTTON_RIGHT)
		{
			if (cline < (lcnt - 1))
			{
				if (lcnt <= 4 || cline >= (lcnt - 5))
				{
					cline = lcnt - 1;
				} else {
					cline += 4;
				}
				
				browser(cpath, ent, cline, lcnt);
			}
		}
		
		/* Enter parent dir */
		if (pressed & WPAD_BUTTON_B)
		{
			if (strlen(cpath) > 6)
			{
				for (i = strlen(cpath); cpath[i] != '/'; i--);
				
				cpath[i] = 0;
				cline = 0;
				
				getdir_info(cpath, &ent, &lcnt);
				create_name_list(cpath, ent, lcnt);
				browser(cpath, ent, cline, lcnt);
			}
		}
		
		/* Enter dir */
		if (pressed & WPAD_BUTTON_A)
		{
			// Is the current entry a dir?
			if (lcnt != 0 && ent[cline].type == DIRENT_T_DIR)
			{
				snprintf(tmp, MAX_CHARACTERS(tmp), cpath);
				snprintf(cpath, MAX_CHARACTERS(cpath), "%s/%s", tmp, ent[cline].name);
				
				ret = getdir_info(cpath, &ent, &lcnt);
				if (ret == 0)
				{
					cline = 0;
					create_name_list(cpath, ent, lcnt);
				} else {
					lcnt = 0;
				}
				
				browser(cpath, ent, cline, lcnt);
			}
		}
		
		/* Dump options */
		if (pressed & WPAD_BUTTON_1)
		{
			if (lcnt != 0 && strlen(cpath) == 15)
			{
				dump_menu(cpath, cline, ent);
				browser(cpath, ent, cline, lcnt);
			}
		}
		
		/* Change view mode */
		if (pressed & WPAD_BUTTON_2)
		{
			ascii ^= 1;
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Switch to content.bin conversion */
		if (pressed & WPAD_BUTTON_PLUS)
		{
			sd_browser();
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Device menu */
		if (pressed & WPAD_BUTTON_MINUS)
		{
			Device_Menu(true);
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Chicken out */
		if (pressed & WPAD_BUTTON_HOME)
		{
			free(ent);
			break;
		}
	}
	
	printf("\nExiting...");
	
	/* End of app loop */
}
