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

int lang;
u8 region;
char titlename[64], ascii_id[5];
bool ftik = false, ftmd = false, change_region = false, ascii = false;
char *languages[10] = { "Japanese", "English", "German", "French", "Spanish", "Italian", "Dutch", "Simp. Chinese", "Trad. Chinese", "Korean" };

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
		strncpy(buf, path, (u32)(next-path));
		buf[(u32)(next-path)] = 0;
		
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
	
	if (hdr1->type == hdr2->type)
	{
		return strcmp(hdr1->name, hdr2->name);
	} else {
		if (hdr1->type == DIRENT_T_DIR)
		{
			return -1;
		} else {
			return 1;
		}
	}
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
		logfile("ES_GetStoredTMDSize for '%08x-%08x' failed (%d).\n", TITLE_UPPER(titleid), TITLE_LOWER(titleid), ret);
		return 0;
	}
	
	tmdbuf = allocate_memory(tmd_size);
	
	ret = ES_GetStoredTMD(titleid, tmdbuf, tmd_size);
	if (ret < 0)
	{
		//printf("ES_GetStoredTMD for '%08x-%08x' failed (%d).\n", TITLE_UPPER(titleid), TITLE_LOWER(titleid), ret);
		logfile("ES_GetStoredTMD for '%08x-%08x' failed (%d).\n", TITLE_UPPER(titleid), TITLE_LOWER(titleid), ret);
		free(tmdbuf);
		return 0;
	}
	
	version = ((tmd*)SIGNATURE_PAYLOAD(tmdbuf))->title_version;
	logfile("version = %u\n", version);
	free(tmdbuf);
	
	return version;
}

s32 getdir_info(char *path, dirent_t **ent, u32 *cnt)
{
	s32 res;
	u32 num = 0;
	char pbuf[ISFS_MAXPATH + 1], ebuf[ISFS_MAXPATH + 1];
	
	int i, j, k;
	
	logfile("\n[GETDIR_INFO] Path = %s. ", path);
	
	/* Get number of entries in this directory */
	res = ISFS_ReadDir(path, NULL, &num);
	if (res != ISFS_OK)
	{
		//printf("Error: could not get dir entry count! (result: %d)\n", res);
		logfile("\nError: could not get dir entry count! (result: %d)\n", res);
		return -1;
	}
	
	/* No entries found */
	if (num == 0)
	{
		logfile("No files/directories found.\n");
		return -1;
	}
	
	/* Allocate memory for the name list */
	char *nbuf = (char *)allocate_memory((ISFS_MAXPATH + 1) * num);
	if (nbuf == NULL)
	{
		//printf("Error: could not allocate buffer for name list!\n");
		logfile("\nError: could not allocate buffer for name list!\n");
		return -1;
	}
	
	/* Read entries */
	res = ISFS_ReadDir(path, nbuf, &num);
	if (res != ISFS_OK)
	{
		//printf("Error: could not get name list! (result: %d)\n", res);
		logfile("\nError: could not get name list! (result: %d)\n", res);
		return -1;
	}
	
	/* Save number of entries */
	*cnt = num;
	
	/* Avoid possible buffer overflow by freeing the entry buffer before reusing it */
	if (*ent != NULL) free(*ent);
	*ent = allocate_memory(sizeof(dirent_t) * num);
	
	logfile("Directory list:\n");
	for(i = 0, k = 0; i < num; i++)
	{
		for (j = 0; nbuf[k] != 0; j++, k++) ebuf[j] = nbuf[k];
		ebuf[j] = 0;
		k++;
		
		sprintf((*ent)[i].name, "%s", ebuf);
		sprintf(pbuf, "%s/%s", path, ebuf);
		logfile("%s\n", pbuf);
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
	
	logfile("\n");
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
		logfile("Error allocating memory for buffer.\n");
		goodbye();
	}
	
	memset(buffer, 0x00, sizeof(IMET));
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	snprintf(titlename, MAX_CHARACTERS(titlename), "Channel/Title deleted from Wii Menu? (couldn't get info)");
	
	ret = getdir_info(path, &list, &num);
	if (ret < 0)
	{
		//printf("Reading folder of the title failed.\n");
		logfile("Reading folder of the title failed.\n");
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
				logfile("ISFS_Open for '%s' failed (%d).\n", path, cfd);
				continue;
			}
			
			ret = ISFS_GetFileStats(cfd, &status);
			if (ret < 0)
			{
				//printf("ISFS_GetFileStats(fd) returned %d.\n", ret);
				logfile("ISFS_GetFileStats(fd) returned %d.\n", ret);
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
					logfile("ISFS_Read(wibn_magic) returned %d.\n", ret);
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
						logfile("ISFS_Read(imet_magic) returned %d.\n", ret);
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
					logfile("ISFS_Read(buffer) returned %d.\n", ret);
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
						logfile("Error allocating memory for dlc_data.\n");
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
						logfile("Error allocating memory for banner_data.\n");
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
							snprintf(titlename, MAX_CHARACTERS(titlename), "%s", str[lang * 2]);
						}
					} else {
						/* Default to English */
						if (get_description && strlen(str[3]) > 1)
						{
							snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", str[2], str[3]);
						} else {
							snprintf(titlename, MAX_CHARACTERS(titlename), "%s", str[2]);
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
		logfile("ISFS_Open for '%s' failed (%d).\n", path, cfd);
		return titlename;
	}
	
	WIBN *save_data = allocate_memory(sizeof(WIBN));
	if (save_data == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\n");
		goodbye();
	}
	
	ret = ISFS_Read(cfd, save_data, sizeof(WIBN));
	if (ret < 0)
	{
		//printf("ISFS_Read for '%s' failed (%d).\n", path, ret);
		logfile("ISFS_Read for '%s' failed (%d).\n", path, ret);
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
	u32 high = TITLE_UPPER(titleid);
	
	if (high == 0x00010000 && TITLE_LOWER(titleid) != 0x48415a41)
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
		logfile("\nError allocating memory for buf.\n");
		fclose(cnt_bin);
		goodbye();
	}
	
	fread(buf, sizeof(IMET), 1, cnt_bin);
	
	ret = aes_128_cbc_decrypt(sd_key, sd_iv, (u8*)buf, sizeof(IMET));
	if (ret < 0)
	{
		//printf("\nError decrypting data.\n");
		logfile("\nError decrypting data.\n");
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
			snprintf(titlename, MAX_CHARACTERS(titlename), "%s", str[lang * 2]);
		}
	} else {
		/* Default to English */
		if (get_description && strlen(str[3]) > 1)
		{
			snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", str[2], str[3]);
		} else {
			snprintf(titlename, MAX_CHARACTERS(titlename), "%s", str[2]);
		}
	}
	
	free(buf);
	
	return titlename;
}

u32 pad_data(void *ptr, u32 len, bool pad_16)
{
	u32 new_size = (pad_16 ? round16(len) : round64(len));
	u32 diff = new_size - len;
	
	if (diff > 0)
	{
		ptr = realloc(ptr, new_size);
		if (ptr != NULL)
		{
			logfile("Memory buffer size reallocated successfully.\n");
			memset(ptr + len, 0x00, diff);
		} else {
			printf("\nError reallocating memory buffer.");
			logfile("Error reallocating memory buffer.");
			free(ptr);
			goodbye();
		}
	}
	
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
		logfile("ISFS_Open for '%s' returned %d.\n", path, fd);
		return -1;
	}
	
	ret = ISFS_GetFileStats(fd, &status);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("ISFS_GetFileStats(fd) returned %d.\n", ret);
		ISFS_Close(fd);
		return -1;
	}
	
	if (status.file_length == 0)
	{
		ISFS_Close(fd);
		return -1;
	}
	
	*size = status.file_length;
	logfile("Size = %u bytes.\n", *size);
	
	*out = allocate_memory(*size);
	if (*out == NULL) 
	{ 
		//printf("Error allocating memory for out.\n");
		logfile("\nError allocating memory for out.\n");
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
			logfile("\nISFS_Read(%d, %d) returned %d.\n", fd, blksize, ret);
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
		//logfile("\nSHA1(%p, %x, %p)\n", p_tmd, TMD_SIZE(p_tmd), hash);
		SHA1((u8 *)p_tmd, TMD_SIZE(p_tmd), hash);
		
		if (hash[0]==0)
		{
			logfile("Setting fill3 to %04hx... ", fill);
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
		//logfile("\nSHA1(%p, %x, %p)\n", p_tmd, TMD_SIZE(p_tmd), hash);
		SHA1((u8 *)p_tik, sizeof(tik), hash);
		
		if (hash[0]==0)
		{
			logfile("Setting padding to %04hx... ", fill);
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

void forge(signed_blob *data, bool is_tmd)
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
		
		printf("Forged %s signature. ", (is_tmd ? "TMD" : "Ticket"));
		logfile("Forged %s signature. ", (is_tmd ? "TMD" : "Ticket"));
	} else {
		printf("%s already fakesigned. ", (is_tmd ? "TMD" : "Ticket"));
		logfile("%s already fakesigned. ", (is_tmd ? "TMD" : "Ticket"));
	}
	
	u8 *ptr = (u8*)data;
	if (is_tmd && change_region)
	{
		/* Change WAD region */
		ptr[0x19D] = region;
		printf("Region changed to 0x%02x. ", region);
		logfile("Region changed to 0x%02x. ", region);
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
		logfile("ES_GetStoredTMDSize for '%08x-%08x' failed (%d).\n", TITLE_UPPER(id), TITLE_LOWER(id), ret);
		return -1;
	}
	
	logfile("TMD size = %u.\n", tmd_size);
	header->tmd_len = tmd_size;
	*tmd = allocate_memory(tmd_size);
	
	ret = ES_GetStoredTMD(id, *tmd, tmd_size);
	if (ret < 0)
	{
		//printf("ES_GetStoredTMD for '%08x-%08x' failed (%d).\n", TITLE_UPPER(id), TITLE_LOWER(id), ret);
		logfile("ES_GetStoredTMD for '%08x-%08x' failed (%d).\n", TITLE_UPPER(id), TITLE_LOWER(id), ret);
		free(*tmd);
		return -1;
	}
	
	if ((tmd_size % 64) != 0)
	{
		tmd_size = pad_data(*tmd, tmd_size, false);
		logfile("Padded TMD size = %u.\n", tmd_size);
	}
	
	/* Fakesign TMD if the user chose to */
	if (ftmd) forge(*tmd, true);
	
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
	
	logfile("Ticket path is '%s'.\n", path);
	s32 ret = read_isfs(path, &buffer, &tik_size);
	if (ret < 0)
	{
		printf("Error getting Ticket!\n");
		return -1;
	}
	
	header->tik_len = tik_size;
	
	if ((tik_size % 64) != 0)
	{
		tik_size = pad_data(buffer, tik_size, false);
		logfile("Padded Ticket size = %u.\n", tik_size);
	}
	
	/* Fakesign ticket if the user chose to */
	if (ftik) forge((signed_blob *)buffer, false);
	
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

s32 GetContent(FILE *f, u64 id, u16 content, u8* key, u16 index, u32 size)
{
	char path[ISFS_MAXPATH];
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content/%08x.app", TITLE_UPPER(id), TITLE_LOWER(id), content);
	logfile("Regular content path is '%s'.\n", path);
	printf("Adding regular content %08x.app... ", content);
	
	s32 fd = ISFS_Open(path, ISFS_OPEN_READ);
	if (fd < 0)
	{
		logfile("ISFS_Open for '%s' returned %d.\n", path, fd);
		return -1;
	}
	
	u32 blksize = BLOCKSIZE; // 16 KB
	
	u8 *buffer = allocate_memory(blksize);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\n");
		ISFS_Close(fd);
		fclose(f);
		goodbye();
	}
	
	int ret = 0;
	u32 i, pad, size2 = 0;
	
	static u8 iv[16];
	memset(iv, 0, 16);
	memcpy(iv, &index, 2);
	
	logfile("Writing...\n");
	for (i = 0; i < size; i += blksize)
	{
		if (blksize > size - i) blksize = size - i;
		
		/* Save the last 16 bytes of the previous encrypted chunk to use them as the IV for the next one */
		if (i > 0) memcpy(iv, &(buffer[BLOCKSIZE - 16]), 16);
		
		ret = ISFS_Read(fd, buffer, blksize);
		if (ret < 0) break;
		
		/* Pad data to a 16-byte boundary (required for the encryption process). Probably only needed for the last chunk */
		if ((blksize % 16) != 0)
		{
			pad = 16 - blksize % 16;
			memset(&(buffer[blksize]), 0x00, pad);
			blksize += pad;
		}
		
		ret = aes_128_cbc_encrypt(key, iv, buffer, blksize);
		if (ret < 0) break;
		
		/* Pad data to a 64-byte boundary (required for the WAD alignment). Again, probably only needed for the last chunk */
		if ((blksize % 64) != 0)
		{
			pad = 64 - blksize % 64;
			memset(&(buffer[blksize]), 0x00, pad);
			blksize += pad;
		}
		
		fwrite(buffer, blksize, 1, f);
		
		size2 += blksize;
	}
	
	free(buffer);
	ISFS_Close(fd);
	
	if (ret < 0) return -1;
	
	logfile("Content added successfully. Original content size: %u bytes. size2: %u bytes.\n", size, size2);
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
		logfile("\nError opening '/shared1/content.map' for reading.");
		goodbye();
	}
	
	content_map_size = status.file_length;
	
	logfile("content.map size = %u bytes.\nWriting '/shared1/content.map' to memory buffer... ", content_map_size);
	buf = allocate_memory(content_map_size);
	if (buf != NULL)
	{
		ISFS_Read(fd, (char*)buf, content_map_size);
		logfile("done.\n");
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
			logfile("Found shared content! Path is '%s'.\nReading... ", path);
			ret = read_isfs(path, &shared_buf, &shared_size);
			if (ret < 0) return -1;
			logfile("done.\n");
			
			if ((shared_size % 16) != 0)
			{
				/* Required for the encryption process */
				logfile("Padding decrypted data to a 16-byte boundary... ");
				shared_size = pad_data(shared_buf, shared_size, true);
				logfile("done. New size: %u bytes.\n", shared_size);
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
			
			if ((shared_size % 64) != 0)
			{
				/* Required for the WAD alignment */
				logfile("Padding encrypted data to a 64-byte boundary... ");
				shared_size = pad_data(shared_buf, shared_size, false);
				logfile("done. New size: %u bytes.\n", shared_size);
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
			logfile("done. Content added successfully.\n");
			
			header->data_len += shared_size;
			free(shared_buf);
			break;
		}
	}
	
	if (found == false)
	{
		printf("\nCould not find the shared content, no hash did match!");
		logfile("Could not find the shared content, no hash did match!\n");
		logfile("\nSHA1 of not found content: ");
		hex_key_dump(hash, 20);
		return -1;
	}
	
	printf("done.\n");
	return 0;
}

s32 GetContentFromCntBin(FILE *cnt_bin, FILE *wadout, u16 index, u32 size, u8 *key)
{
	u32 rounded_size = round64(size);
	u32 blksize = SD_BLOCKSIZE; // 32 KB
	
	u8 *buffer = allocate_memory(blksize);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\n");
		fclose(cnt_bin);
		fclose(wadout);
		goodbye();
	}
	
	int ret = 0;
	u32 i, pad;
	
	static u8 iv1[16];
	memset(iv1, 0, 16);
	memcpy(iv1, &index, 2);
	
	static u8 iv2[16];
	memset(iv2, 0, 16);
	memcpy(iv2, &index, 2);
	
	logfile("Writing...\n");
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
		
		/* Only do this if the content needs padding */
		if ((rounded_size - size) > 0)
		{
			/* Check if this is the last chunk */
			if ((i + blksize - (rounded_size - size)) == size)
			{
				/* Pad data to a 16-byte boundary (required for the encryption process) */
				blksize -= (rounded_size - size);
				if ((blksize % 16) != 0)
				{
					pad = 16 - blksize % 16;
					memset(&(buffer[blksize]), 0x00, pad);
					blksize += pad;
				}
			}
		}
		
		ret = aes_128_cbc_encrypt(key, iv2, buffer, blksize);
		if (ret < 0) break;
		
		/* Save the last 16 bytes of the previous encrypted chunk to use them as the IV for aes_128_cbc_encrypt */
		memcpy(iv2, &(buffer[SD_BLOCKSIZE - 16]), 16);
		
		/* Pad data to a 64-byte boundary (required for the WAD alignment). Probably only needed for the last chunk */
		if ((blksize % 64) != 0)
		{
			pad = 64 - blksize % 64;
			memset(&(buffer[blksize]), 0x00, pad);
			blksize += pad;
		}
		
		fwrite(buffer, blksize, 1, wadout);
	}
	
	free(buffer);
	if (ret < 0) return -1;
	
	logfile("Content added successfully. Original content size: %u bytes. rounded_size: %u bytes.\n", size, rounded_size);
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
	logfile("\n[GETDIR_DEVICE] Path = %s. ", path);
	
	u32 i = 0;
	DIR *dip;
    struct dirent *dit;
	char pbuf[ISFS_MAXPATH + 1];
	
	if ((dip = opendir(path)) == NULL)
    {
		//printf("\nError opening '%s'.\n", path);
		logfile("\nError opening '%s'.\n", path);
		sleep(3);
        return -1;
    }
	
    while ((dit = readdir(dip)) != NULL) i++;
	
	if (i == 0)
	{
		logfile("No files/directories found.\n");
		closedir(dip);
		return -2;
	}
	
	rewinddir(dip);
	
	if (*ent) free(*ent);
	*ent = allocate_memory(sizeof(dirent_t) * i);
	if (*ent == NULL)
	{
		logfile("Error allocating memory for *ent.\n");
		closedir(dip);
		return -1;
	}
	
	i = 0;
	
	logfile("Directory list:\n");
    while ((dit = readdir(dip)) != NULL)
    {
		if (strncmp(dit->d_name, ".", 1) != 0 && strncmp(dit->d_name, "..", 2) != 0)
		{
			strcpy((*ent)[i].name, dit->d_name);
			sprintf(pbuf, "%s/%s", path, dit->d_name);
			logfile("%s\n", pbuf);
			(*ent)[i].type = ((isdir_device(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
			(*ent)[i].function = TYPE_OTHER;
			i++;
		}	
    }
	
	logfile("\n");
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
		logfile("Error allocating memory for buffer.\n");
		goodbye();
	}
	
	int fd = ISFS_Open(source, ISFS_OPEN_READ);
	if (fd < 0) 
	{
		//printf("\nError: ISFS_OpenFile for '%s' returned %d.\n", source, fd);
		logfile("\nError: ISFS_OpenFile for '%s' returned %d.\n", source, fd);
		return fd;
	}

	FILE *file = fopen(destination, "wb");
	if (!file)
	{
		//printf("\nError: fopen for '%s' returned 0 .\n", destination);
		logfile("\nError: fopen '%s' returned 0.\n", destination);
		ISFS_Close(fd);
		return -1;
	}
	
	ret = ISFS_GetFileStats(fd, &status);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		ISFS_Close(fd);
		fclose(file);
		remove(destination);
		return ret;
	}
	
	Con_ClearLine();
	printf("Dumping '%s' / Size = %uKB", source, (status.file_length / 1024)+1);
	logfile("Dumping '%s' / Size = %uKB", source, (status.file_length / 1024)+1);
	
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
			logfile("\nISFS_Read(%d, %p, %d) returned %d.\n", fd, buffer, size, ret);
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
			logfile("\nfwrite error: %d.\n", ret);
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
		logfile("Error allocating memory for buffer.\n");
		goodbye();
	}
	
	FILE *file = fopen(source, "rb");
	if (!file) 
	{
		printf("Error opening '%s' for reading.\n", source);
		logfile("Error opening '%s' for reading.\n", source);
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
		logfile("ISFS_Open('%s', WRITE) error: %d.\n", destination, nandfile);
		fclose(file);
		free(buffer);
		return -1;
	}
	
	Con_ClearLine();
	printf("Flashing '%s' / Size = %uKB", destination, (filesize / 1024)+1);
	logfile("Flashing '%s' / Size = %uKB", destination, (filesize / 1024)+1);
	
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
			logfile("Error reading data from '%s' (ret = %d).\n", source, ret);
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
			logfile("ISFS_Write('%s') error: %d.\n", destination, ret);
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
		logfile("ISFS_Open('%s', READ) error: %d.\n", destination, nandfile);
		ISFS_Delete(destination);
		return -1;
	}	
	
	ret = ISFS_GetFileStats(nandfile, &stats);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("ISFS_GetFileStats(fd) returned %d.\n", ret);
		ISFS_Close(nandfile);
		ISFS_Delete(destination);
		return -1;
	}
	
	printf("Flashing file to NAND successful! New file is %u bytes.\n", stats.file_length);
	logfile("Flashing file to NAND successful! New file is %u bytes.\n", stats.file_length);
	
	ISFS_Close(nandfile);*/
	
	return 0;
}

bool dumpfolder(char source[1024], char destination[1024])
{
	//logfile("\n[DUMPFOLDER] Source : '%s' / Destination: '%s'.\n", source, destination);
	
	int i;
	u32 tcnt;
	s32 ret;
	char path[1024], path2[1024];
	dirent_t *dir = NULL;
	
	ret = getdir_info(source, &dir, &tcnt);
	if (ret < 0)
	{
		printf("Error reading source directory.\n");
		logfile("Error reading source directory.\n");
		if (dir) free(dir);
		return false;
	}
	
	remove(destination);
	
	for (i = 0; i < tcnt; i++) 
	{
		snprintf(path, MAX_CHARACTERS(path), "%s/%s", source, dir[i].name);
		
		if (strncmp(dir[i].name, "title.tmd", 9) != 0)
		{
			logfile("\nSource file is '%s'.\n", path);
			
			snprintf(path2, MAX_CHARACTERS(path2), "%s/%s", destination, dir[i].name);
			
			if (!create_folders(path2))
			{
				//printf("Error creating folder(s) for '%s'.\n", path2);
				logfile("Error creating folder(s) for '%s'.\n", path2);
				return false;
			}
			
			if (dir[i].type == DIRENT_T_FILE) 
			{
				logfile("Destination file is '%s'.\n", path2);
				ret = dumpfile(path, path2);
				if (ret < 0)
				{
					printf("Error dumping file from NAND.\n");
					logfile("Error dumping file from NAND.\n");
					free(dir);
					return false;
				}
			} else {
				logfile("Destination dir is '%s'.\n", path2);
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
			logfile("title.tmd detected in '%s' automatically deleted.\n", source);
		}
	}
	
	free(dir);
	return true;
}

bool writefolder(char *source, char *destination)
{
	//logfile("\n[WRITEFOLDER] Source : '%s' / Destination: '%s'.\n", source, destination);
	
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
		logfile("Error reading source directory.\n");
		if (dir) free(dir);
		return false;
	}
	
	ret = ISFS_Delete(destination);
	logfile("ISFS_Delete('%s') returned %d.\n", destination, ret);
	ret = ISFS_CreateDir(destination, 0, 3, 3, 3);
	logfile("ISFS_CreateDir('%s', 0, 3, 3, 3) returned %d.\n", destination, ret);
	
	for (i = 0; i < tcnt; i++) 
	{
		/* We'll flash the title.tmd file separately in install_savedata() */
		if (strncmp(dir[i].name, "title.tmd", 9) != 0)
		{
			snprintf(path, MAX_CHARACTERS(path), "%s/%s", source, dir[i].name);
			logfile("Source file is '%s'.\n", path);
			
			snprintf(path2, MAX_CHARACTERS(path2), "%s/%s", destination, dir[i].name);
			
			if (dir[i].type == DIRENT_T_FILE)
			{
				logfile("Destination file is '%s'.\n", path2);
				ret = flash(path, path2);
				if (ret < 0)
				{
					printf("Error flashing file to NAND.\n");
					logfile("Error flashing file to NAND.\n");
					free(dir);
					return false;
				}
			} else {
				logfile("Destination dir is '%s'.\n", path2);
				
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
		// libFAT has problems reading and writing filenames with Unicode characters, like "é"
		if (memchr("?[]/\\=+<>:;\",*|^", name[i], sizeof("?[]/\\=+<>:;\",*|^") - 1) || name[i] < 0x20 || name[i] > 0x7E) name[i] = '_';
	}
	return name;
}

void extract_savedata(u64 titleID)
{
	s32 ret;
	char *id = GetASCII(TITLE_LOWER(titleID));
	char isfs_path[ISFS_MAXPATH], dev_path[MAXPATHLEN]; // source, destination
	
	logfile("Extracting title %08x-%08x...\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS path is '%s'.\n", isfs_path);
	
	if (TITLE_UPPER(titleID) == 0x00010000)
	{
		//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/DISC %s", DEVICE(0), id);
		snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/DISC %s - %s", DEVICE(0), id, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: disc-based game.\n");
	} else
	if (TITLE_UPPER(titleID) == 0x00010001)
	{
		/* Workaround for HBC 1.0.7 - 1.1.0*/
		if (TITLE_LOWER(titleID) == 0xAF1BF516)
		{
			//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN AF1BF516", DEVICE(0));
			snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN AF1BF516 - Homebrew Channel", DEVICE(0));
			logfile("Savedata type: The Homebrew Channel (1.0.7 - 1.1.0).\n");
		} else {
			//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN %s", DEVICE(0), id);
			snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHAN %s - %s", DEVICE(0), id, RemoveIllegalCharacters(get_name(titleID, false)));
			logfile("Savedata type: downloaded channel title.\n");
		}
	} else
	if (TITLE_UPPER(titleID) == 0x00010004)
	{
		//snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHSV %s", DEVICE(0), id);
		snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s:/YABDM/Savedata/CHSV %s - %s", DEVICE(0), id, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: game that uses channel.\n");
	}
	
	logfile("%s path is '%s'.\n", DEVICE(1), dev_path);
	
	if (dumpfolder(isfs_path, dev_path))
	{
		/* Dump the title.tmd file */
		snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
		strncat(dev_path, "/title.tmd", 10);
		
		logfile("\ntitle.tmd path = %s.\n", isfs_path);
		logfile("path_out = %s.\n", dev_path);
		
		ret = dumpfile(isfs_path, dev_path);
		if (ret < 0)
		{
			printf("\n\nError dumping title.tmd to %s.\n", DEVICE(1));
			logfile("\nError dumping title.tmd to %s.\n", DEVICE(1));
		} else {
			printf("\n\nDumping folder complete.\n");
			logfile("\nDumping folder complete.\n");
		}
	}
}	

void install_savedata(u64 titleID)
{
	s32 ret;
	bool found = false;
	char *id = GetASCII(TITLE_LOWER(titleID));
	char dev_path[MAXPATHLEN], isfs_path[ISFS_MAXPATH]; // source, destination
	
	logfile("Installing title %08x-%08x...\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS path is '%s'.\n", isfs_path);
	
	sprintf(dev_path, "%s:/YABDM/Savedata", DEVICE(0));
	
	/* Search savedata directory on external storage */
	u32 i, tcnt;
	dirent_t *dir = NULL;
	ret = getdir_device(dev_path, &dir, &tcnt);
	if (ret < 0)
	{
		printf("Error reading savedata directory.\n");
		logfile("Error reading savedata directory.\n");
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
		logfile("\nCouldn't find the savedata on the %s!\n", (isSD ? "SD card" : "USB storage"));
		sleep(3);
		return;
	} else {
		logfile("Savedata found: '%s'.\n", dir[i].name);
		snprintf(dev_path, MAX_CHARACTERS(dev_path), "%s/%s", dev_path, dir[i].name);
		logfile("%s path is '%s'.\n", DEVICE(1), dev_path);
	}
	
	if (writefolder(dev_path, isfs_path))
	{
		/* Flash the title.tmd file */
		snprintf(isfs_path, MAX_CHARACTERS(isfs_path), "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
		strncat(dev_path, "/title.tmd", 10);
		
		logfile("\ntitle.tmd path = %s.\n", dev_path);
		logfile("path_out = %s.\n", isfs_path);
		
		ret = flash(dev_path, isfs_path);
		if (ret < 0)
		{
			printf("\n\nError flashing title.tmd to NAND.\n");
			logfile("Error flashing title.tmd to NAND.\n");
		} else {
			printf("\n\nFlashing to NAND complete.\n");
			logfile("\nFlashing to NAND complete.\n");
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
	
	//logfile("\n\nBROWSER: Using Wii NAND. Inserted device: %s.\nPath: %s\n", (isSD ? "SD Card" : "USB Storage"), cpath);
	
	printf("[1/Y] Dump Options  [A] Confirm/Enter Directory  [2/X] Change view mode\n");
	printf("[B] Cancel/Return to Parent Directory  [Home/Start] Exit\n");
	printf("[+/R] Switch to content.bin conversion\n\n");
	
	printf("Path: %s\n\n", cpath);
	
	if (lcnt == 0)
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
		logfile("Error allocating memory for wadheader.\n");
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
	logfile("\nEncrypted Title Key = ");
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
	logfile("\nDecrypted Title Key = ");
	hex_key_dump(keyout, sizeof(keyout));
	logfile("\n");
	
	return 0;
}

s32 Wad_Dump(u64 id, char *path)
{
	make_header();
	
	logfile("Path for dump = %s.\n", path);
	logfile("Started WAD Packing...\nPacking Title %08x-%08x\n", TITLE_UPPER(id), TITLE_LOWER(id));

	signed_blob *p_tik = NULL;
	signed_blob *p_tmd = NULL;
	
	tmd *tmd_data = NULL;
	u8 key[16];
	
	s32 ret;
	u32 cnt;
	
	if (!create_folders(path))
	{
		printf("\nError creating folder(s) for '%s'.\nIs your storage device write protected?\n", path);
		logfile("Error creating folder(s) for '%s'.\n", path);
		return -1;
	}

	FILE *wadout = fopen(path, "wb");
	if (!wadout)
	{
		printf("\nError opening '%s' for writing.\nIs your storage device write protected?\n", path);
		logfile("Error opening '%s' for writing.\n", path);
		free(header);
		return -1;
	}
	
	/* Reserve space for the header */
	u8 *padding_table = allocate_memory(64);
	if (padding_table == NULL)
	{
		//printf("Error allocating memory for padding_table.\n");
		logfile("Error allocating memory for padding_table.\n");
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
	logfile("done.\n");
	
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
	logfile("OK.\n");
	
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
	logfile("OK.\n");
	
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
	logfile("done.\n");
	
	char footer_path[ISFS_MAXPATH];
	
	tmd_data = (tmd *)SIGNATURE_PAYLOAD(p_tmd);
	for (cnt = 0; cnt < tmd_data->num_contents; cnt++)
	{
		printf("Processing content #%u... ", cnt);
		logfile("Processing content #%u... ", cnt);
		tmd_content *content = &tmd_data->contents[cnt];
		
		if (cnt == 0) sprintf(footer_path, "/title/%08x/%08x/content/%08x.app", TITLE_UPPER(id), TITLE_LOWER(id), content->cid);
		
		switch(content->type)
		{
			case 0x0001: // Normal
			case 0x4001: // DLC
				ret = GetContent(wadout, id, content->cid, (u8*)key, content->index, (u32)content->size);
				break;
			case 0x8001: // Shared
				ret = GetSharedContent(wadout, (u8*)key, content->index, content->hash, cm, content_map_items);
				break;
			default:
				printf("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
				logfile("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
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
		logfile("Error reading content!");
		free(header);
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
		logfile("Error getting footer!\n");
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
	logfile("done.\n");
	
	/* Add WAD header */
	printf("Writing header info... ");
	logfile("Writing header info... ");
	rewind(wadout);
	fwrite((u8 *)header, 0x20, 1, wadout);
	printf("done.\n");
	logfile("done.\nHeader hexdump:\n");
	hexdump_log(header, 0x20);
	
	free(header);
	fclose(wadout);
	return 0;
}

s32 Content_bin_Dump(FILE *cnt_bin, char* path)
{
	make_header();
	
	logfile("Path for dump = %s.\n", path);
	logfile("Started WAD Packing...\n");
	
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
		logfile("Error creating folder(s) for '%s'.\n", path);
		return -1;
	}
	
	fseek(cnt_bin, 0, SEEK_END);
	u32 cnt_size = ftell(cnt_bin);
	rewind(cnt_bin);
	
	FILE *wadout = fopen(path, "wb");
	if (!wadout)
	{
		printf("\nError opening '%s' for writing.\nIs your storage device write protected?\n", path);
		logfile("Error opening '%s' for writing.\n", path);
		free(header);
		return -1;
	}
	
	/* Reserve space for the header */
	u8 *padding_table = allocate_memory(64);
	if (padding_table == NULL)
	{
		//printf("\nError allocating memory for padding_table.\n");
		logfile("Error allocating memory for padding_table.\n");
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
	logfile("done.\n");
	
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
			logfile("done.\n");
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
		logfile("\nError allocating memory for temp.");
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
				logfile("\nError: Console ID mismatch. This content.bin file was not generated by this Wii!");
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
		logfile("\nError: Couldn't identify \"Bk\" header in content.bin file.\n");
		free(header);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	printf("done.\n");
	logfile("done.\n");
	
	/* Get TMD */
	printf("Reading TMD... ");
	logfile("Reading TMD... ");
	u8 *tmd_buf = allocate_memory(tmd_size);
	if (tmd_buf == NULL)
	{
		printf("Error allocating memory for p_tmd.\n");
		logfile("Error allocating memory for p_tmd.\n");
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
	
	if (ftmd) forge((signed_blob *)tmd_buf, true);
	p_tmd = (signed_blob *)tmd_buf;
	
	printf("OK.\n");
	logfile("OK.\n");
	
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
	logfile("OK.\n");
	
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
	logfile("done.\n");
	
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
		
		switch (content->type)
		{
			case 0x0001: // Normal
			case 0x4001: // DLC, I'm not sure if this type of content gets included or not, but let's be on the safe side
				printf("Adding regular content %08x... ", content->cid);
				ret = GetContentFromCntBin(cnt_bin, wadout, content->index, (u32)content->size, (u8*)key);
				break;
			case 0x8001: // Shared, they don't get included in the content.bin file
				ret = GetSharedContent(wadout, (u8*)key, content->index, content->hash, cm, content_map_items);
				break;
			default:
				printf("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
				logfile("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
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
		logfile("Error allocating memory for footer_buf.\n");
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
		logfile("Error decrypting footer data.\n");
		free(header);
		free(footer_buf);
		fclose(wadout);
		remove(path);
		return -1;
	}
	
	if ((header->footer_len % 64) != 0) memset(&(footer_buf[header->footer_len]), 0x00, (footer_size - header->footer_len));
	
	fwrite(footer_buf, footer_size, 1, wadout);
	free(footer_buf);
	
	printf("done.\n");
	logfile("done.\n");
	
	/* Add WAD header */
	printf("Writing header info... ");
	logfile("Writing header info... ");
	rewind(wadout);
	fwrite((u8 *)header, 0x20, 1, wadout);
	printf("done.\n");
	logfile("done.\nHeader hexdump:\n");
	hexdump_log(header, 0x20);
	
	free(header);
	fclose(wadout);
	
	return 0;
}

u64 copy_id(char *path)
{
	//logfile("COPY_ID: path = %s.\n", path);
	char *low_out = allocate_memory(10);
	memset(low_out, 0, 10);
	char *high_out = allocate_memory(10);
	memset(high_out, 0, 10);	
	
	strncpy(high_out, path+7, 8);
	strncpy(low_out, path+16, 8);

	u64 titleID = TITLE_ID(strtol(high_out, NULL, 16), strtol(low_out,NULL,16));
	logfile("Generated COPY_ID was '%08x-%08x'.\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	free(low_out);
	free(high_out);
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
			logfile("%s set to true.\n", name);
			break;
		}
		
		if (pressed & WPAD_BUTTON_B)
		{
			*option = false;
			logfile("%s set to false.\n", name);
			break;
		}
	}
}

void select_forge()
{
	YesNoPrompt("Do you want to fakesign the ticket?", "ftik", &ftik);
	YesNoPrompt("Do you want to fakesign the TMD?", "ftmd", &ftmd);
	
	/* WAD region change prompt */
	/* We cannot change the WAD region if the TMD isn't fakesigned */
	if (ftmd)
	{
		YesNoPrompt("Do you also want to change the WAD region?", "change_region", &change_region);
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
				printf("%s", region_str[selection]);
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

void dump_menu(char *cpath, char *tmp, int cline, dirent_t *ent)
{
	u64 titleID;
	u32 pressed;
	
	int selection = 0;
	char *options[3] = { "Backup Savedata >", "< Restore Savedata >" , "< Backup to WAD"};
	
	while(true)
	{
		resetscreen();
		printheadline();
		
		printf("Select what to do: ");
		
		set_highlight(true);
		printf("%s", options[selection]);
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
	
	char some[500];
	strcpy(tmp, cpath);
	if(strcmp(cpath, "/") != 0)
	{
		sprintf(some, "%s/%s", tmp, ent[cline].name);
	} else {				
		sprintf(some, "/%s", ent[cline].name);
	}
	
	logfile("\n[DUMP_MENU] Selected item: %s.\n", some);
	switch(selection)
	{
		case 0: // Backup savedata
			if ((ent[cline].function == TYPE_SAVEDATA && strncmp(ent[cline].name, "48415a41", 8) != 0) || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
			{
				printf("\n\nBacking up savedata...\n\n");
				logfile("Backing up savedata...\n");
				titleID = copy_id(some);
				extract_savedata(titleID);
			} else {
				printf("\n\nThe title you chose has no savedata!\n");
				printf("Use the WAD function for this.");
			}
			break;
		case 1: // Restore savedata
			if ((ent[cline].function == TYPE_SAVEDATA && strncmp(ent[cline].name, "48415a41", 8) != 0) || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
			{
				printf("\n\nRestoring savedata...\n\n");
				logfile("Restoring savedata...\n");
				titleID = copy_id(some);
				install_savedata(titleID);
			} else {
				printf("\n\nThe title you chose has no savedata!\n");
				printf("Use the WAD function for this.");
			}
			break;	
		case 2: // Backup to WAD
			/* Workaround for HAZA (00010000-48415a41) */
			/* This title is responsible for changing the Photo Channel v1.0 placeholder in the System Menu to v1.1 */
			if ((ent[cline].function == TYPE_SAVEDATA && strncmp(ent[cline].name, "48415a41", 8) != 0) || ent[cline].function == TYPE_OTHER)
			{
				printf("\n\nThis is not a title! Use the savedata functions for this.\n");
			} else {
				logfile("\nCreating WAD...\n");
				
				select_forge();
				
				resetscreen();
				printheadline();
				printf("Creating WAD...\n");
				
				char dump_path[100];
				
				switch (ent[cline].function)
				{
					case TYPE_SAVEDATA:
						titleID = TITLE_ID(0x00010000, strtoll(ent[cline].name, NULL, 16));
						break;
					case TYPE_TITLE:
						titleID = TITLE_ID(0x00010001, strtoll(ent[cline].name, NULL, 16));
						break;
					case TYPE_SYSTITLE:
						titleID = TITLE_ID(0x00010002, strtoll(ent[cline].name, NULL, 16));
						break;
					case TYPE_GAMECHAN:
						titleID = TITLE_ID(0x00010004, strtoll(ent[cline].name, NULL, 16));
						break;
					case TYPE_DLC:
						titleID = TITLE_ID(0x00010005, strtoll(ent[cline].name, NULL, 16));
						break;
					case TYPE_HIDDEN:
						titleID = TITLE_ID(0x00010008, strtoll(ent[cline].name, NULL, 16));
						break;
					default: // TYPE_IOS
						titleID = TITLE_ID(0x00000001, strtoll(ent[cline].name, NULL, 16));
						break;
				}
				
				u32 low = TITLE_LOWER(titleID);
				
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
					logfile("WAD dump complete!\n");
					printf("WAD dump complete! Output file:\n\n\t%s", dump_path);
				}
			}
			break;
		default:
			break;
	}
	
	fflush(stdout);
	sleep(3);
}

void sd_browser_ent_info(dirent_t* ent, int cline, int lcnt)
{
	int i;
	resetscreen();
	printheadline();
	
	//logfile("\n\nSD_BROWSER: Using SD card. Inserted device: %s.\nPath: %s\n", (isSD ? "SD Card" : "USB Storage"), SD_ROOT_DIR);
	
	printf("[A] Convert selected title's content.bin file to WAD  [Home/Start] Exit\n");
	printf("[+/R] Return to the main browser screen\n\n");
	
	printf("Path: %s\n\n", SD_ROOT_DIR);
	
	for (i = (cline / 15)*15; i < lcnt && i < (cline / 15)*15+15; i++)
	{
		printf("%s %-12s - %s\n", (i == cline ? ARROW : "  "), ent[i].name, ent[i].titlename);
	}
	
	fflush(stdout);
}

void dump_menu_sd(char *cnt_path)
{
	logfile("\nCreating WAD...\n");
	
	resetscreen();
	printheadline();
	
	select_forge();
	
	resetscreen();
	printheadline();
	printf("Creating WAD...\n");
	
	FILE *cnt_bin = fopen(cnt_path, "rb");
	if (!cnt_bin)
	{
		printf("\nError opening '%s' for reading.\n", cnt_path);
		logfile("\nError opening '%s' for reading.\n", cnt_path);
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
		logfile("WAD dump complete!\n");
		printf("WAD dump complete! Output file:\n\n\t%s", dump_path);
	}
	
	fclose(cnt_bin);
	fflush(stdout);
	sleep(3);
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
	
	ret = getdir_device(SD_ROOT_DIR, &ent, &lcnt);
	if (ret < 0)
	{
		if (ent) free(ent);
		
		if (ret == -2)
		{
			printf("No files/directories found in '%s'!", SD_ROOT_DIR);
			sleep(3);
		}
		
		return;
	}
	
	FILE *f;
	bool cntbin_exists[lcnt];
	
	printf("Loading title names, please wait...");
	
	/* Create name list - Speeds up directory browsing */
	for (i = 0; i < lcnt; i++)
	{
		if (ent[i].type == DIRENT_T_DIR)
		{
			snprintf(tmp, MAX_CHARACTERS(tmp), "%s/%s/content.bin", SD_ROOT_DIR, ent[i].name);
			f = fopen(tmp, "rb");
			if (f)
			{
				cntbin_exists[i] = true;
				snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", read_cntbin_name(f, true));
				fclose(f);
			} else {
				cntbin_exists[i] = false;
				switch(ent[i].name[0])
				{
					case 'R':
					case 'S':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Wii disc-based game data          (content.bin not found)");
						break;
					case 'W':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "WiiWare                           (content.bin not found)");
						break;
					case 'X':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "MSX VC / WiiWare Demo             (content.bin not found)");
						break;
					case 'P':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "TurboGraFX VC                     (content.bin not found)");
						break;
					case 'Q':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "TurboGraFX CD VC                  (content.bin not found)");
						break;
					case 'N':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Nintendo 64 VC                    (content.bin not found)");
						break;
					case 'M':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Sega Genesis / Megadrive VC       (content.bin not found)");
						break;
					case 'L':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Sega Master System VC             (content.bin not found)");
						break;
					case 'J':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Super Nintendo VC                 (content.bin not found)");
						break;
					case 'H':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Wii Channel / System Title        (content.bin not found)");
						break;
					case 'F':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "NES / Famicom VC                  (content.bin not found)");
						break;
					case 'E':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "VC Arcade / NeoGeo                (content.bin not found)");
						break;
					case 'C':
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "Commodore 64 VC                   (content.bin not found)");
						break;
					default:
						snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "*** Unknown Title Type ***        (content.bin not found)");
						break;
				}
			}
		} else {
			cntbin_exists[i] = false;
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "File");
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
			if(cline > 0) 
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
			if(cline < (lcnt - 1))
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
			if (cline >= 4)
			{
				cline -= 4;
			} else {
				cline = 0;
			}
			
			sd_browser_ent_info(ent, cline, lcnt);
		}
		
		/* Navigate right */
		if (pressed & WPAD_BUTTON_RIGHT)
		{
			if (cline <= (lcnt - 5))
			{
				cline += 4;
			} else {
				cline = lcnt - 1;
			}
			
			sd_browser_ent_info(ent, cline, lcnt);
		}
		
		/* Start conversion to WAD */
		if (pressed & WPAD_BUTTON_A)
		{
			if (ent[cline].type == DIRENT_T_DIR && cntbin_exists[cline] == true)
			{
				snprintf(tmp, MAX_CHARACTERS(tmp), "%s/%s/content.bin", SD_ROOT_DIR, ent[cline].name);
				dump_menu_sd(tmp);
				sd_browser_ent_info(ent, cline, lcnt);
			}
		}
		
		/* Return to the main browser screen */
		if (pressed & WPAD_BUTTON_PLUS) break;
		
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
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", get_name(TITLE_ID(0x00010000, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_TITLE)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", get_name(TITLE_ID(0x00010001, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_SYSTITLE)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", get_name(TITLE_ID(0x00010002, strtoll(ent[i].name, NULL, 16)), false));
		} else
		if (ent[i].function == TYPE_GAMECHAN)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", get_name(TITLE_ID(0x00010004, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_DLC)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", get_name(TITLE_ID(0x00010005, strtoll(ent[i].name, NULL, 16)), true));
		} else
		if (ent[i].function == TYPE_OTHER)
		{
			snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", (ent[i].type == DIRENT_T_DIR ? "Directory" : "File"));
		}
	}
}

void yabdm_loop(void)
{
	reset_log();
	logfile("Yet Another BlueDump MOD v%s - Logfile.\n", VERSION);
	logfile("SDmnt(%d), USBmnt(%d), isSD(%d).\n", SDmnt, USBmnt, isSD);
	logfile("Using IOS%u v%u.\n", IOS_GetVersion(), IOS_GetRevision());
	
	/* Get Console Language */
	lang = CONF_GetLanguage();
	logfile("Console language: %d (%s).\n\n", lang, languages[lang]);
	
	/* Read the content.map file here to avoid reading it at a later time */
	GetContentMap();
	if (cm == NULL || content_map_size == 0)
	{
		printf("\n\nError loading '/shared1/content.map', size = 0.");
		logfile("\nError loading '/shared1/content.map', size = 0.");
		goodbye();
	}
	
	content_map_items = content_map_size/sizeof(map_entry_t);
	
	int i = 0;
	char tmp[ISFS_MAXPATH + 1];
	char cpath[ISFS_MAXPATH + 1];
	dirent_t* ent = NULL;
	u32 pressed, lcnt = 0, cline = 0;
	
	sprintf(cpath, ROOT_DIR);
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
			if(cline > 0) 
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
			if(cline < (lcnt - 1))
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
			if (cline >= 4)
			{
				cline -= 4;
			} else {
				cline = 0;
			}
			
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Navigate right */
		if (pressed & WPAD_BUTTON_RIGHT)
		{
			if (cline <= (lcnt - 5))
			{
				cline += 4;
			} else {
				cline = lcnt - 1;
			}
			
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Enter parent dir */
		if (pressed & WPAD_BUTTON_B)
		{
			if (strlen(cpath) > 6)
			{
				for(i = strlen(cpath); cpath[i] != '/'; i--);
				
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
			if (ent[cline].type == DIRENT_T_DIR)
			{
				strcpy(tmp, cpath);
				if (strcmp(cpath, "/") != 0)
				{
					sprintf(cpath, "%s/%s", tmp, ent[cline].name);
				} else {				
					sprintf(cpath, "/%s", ent[cline].name);
				}
				
				getdir_info(cpath, &ent, &lcnt);
				create_name_list(cpath, ent, lcnt);
				
				cline = 0;
				browser(cpath, ent, cline, lcnt);
			}
		}
		
		/* Dump options */
		if (pressed & WPAD_BUTTON_1)
		{
			if (lcnt != 0 && strlen(cpath) == 15)
			{
				dump_menu(cpath, tmp, cline, ent);
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
