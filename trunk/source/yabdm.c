/*******************************************************************************
 * yabdm.c                                                                     *
 *                                                                             *
 * Copyright (c) 2009 Nicksasa                                                 *
 *                                                                             *
 * Modified by DarkMatterCore [PabloACZ] (2013)                                *
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
//const u8 sd_iv[16] = { 0x21, 0x67, 0x12, 0xe6, 0xaa, 0x1f, 0x68, 0x9f, 0x95, 0xc5, 0xa2, 0x23, 0x24, 0xdc, 0x6a, 0x98 };

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

bool create_folders(char *path)
// Creates the required folders for a filepath
// Example: Input "sd:/YABDM/00000001/test.bin" creates "sd:/YABDM" and "sd:/YABDM/00000001"
{
	char *last = strrchr(path, '/');
	char *next = strchr(path,'/');
	if (last == NULL)
	{
		return true;
	}
	char buf[256];
	
	while (next != last)
	{
		next = strchr((char *)(next+1),'/');
		strncpy(buf, path, (u32)(next-path));
		buf[(u32)(next-path)] = 0;
		
		if (!MakeDir(buf))
		{
			return false;
		}
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
	
	if(res < 0) return 0;
	
	return 1;
}

u16 get_version(u64 titleid)
{
	char buffer[64];
	s32 cfd;
	s32 ret;
	u16 version;
	u8 *tmdbuf = (u8*)memalign(32, 1024);
	
	snprintf(buffer, MAX_CHARACTERS(buffer), "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	
	logfile("get_version path: %s\n", buffer);
	cfd = ISFS_Open(buffer, ISFS_OPEN_READ);
    if (cfd < 0)
	{
		//printf("ISFS_OPEN for '%s' failed (%d).\n", buffer, cfd);
		logfile("ISFS_OPEN for '%s' failed (%d).\n", buffer, cfd);
		Unmount_Devices();
		Reboot();
	}
	
    ret = ISFS_Read(cfd, tmdbuf, 1024);
	if (ret < 0)
	{
		//printf("ISFS_Read for '%s' failed (%d).\n", buffer, ret);
		logfile("ISFS_Read for '%s' failed (%d).\n", buffer, ret);
		ISFS_Close(cfd);
		Unmount_Devices();
		Reboot();
	}

    ISFS_Close(cfd);
	memcpy(&version, tmdbuf+0x1DC, 2);
	logfile("version = %u\n", version);
	free(tmdbuf);
	return version;
}

s32 getdir_info(char *path, dirent_t **ent, u32 *cnt)
{
	s32 res;
	u32 num = 0;
	char pbuf[ISFS_MAXPATH + 1];
	
	int i, j, k;
	
	res = ISFS_ReadDir(path, NULL, &num);
	if(res != ISFS_OK)
	{
		//printf("Error: could not get dir entry count! (result: %d)\n", res);
		logfile("Error: could not get dir entry count! (result: %d)\n", res);
		return -1;
	}
	
	char *nbuf = (char *)allocate_memory((ISFS_MAXPATH + 1) * num);
	char ebuf[ISFS_MAXPATH + 1];
	
	if(nbuf == NULL)
	{
		//printf("Error: could not allocate buffer for name list!\n");
		logfile("Error: could not allocate buffer for name list!\n");
		return -1;
	}
	
	res = ISFS_ReadDir(path, nbuf, &num);
	if(res != ISFS_OK)
	{
		//printf("Error: could not get name list! (result: %d)\n", res);
		logfile("Error: could not get name list! (result: %d)\n", res);
		return -1;
	}
	
	*cnt = num;
	if (*ent != NULL) free(*ent);
	*ent = allocate_memory(sizeof(dirent_t) * num);
	logfile("\nISFS DIR list of '%s':\n\n", path);
	for(i = 0, k = 0; i < num; i++)
	{
		for(j = 0; nbuf[k] != 0; j++, k++) ebuf[j] = nbuf[k];
		ebuf[j] = 0;
		k++;
		
		sprintf((*ent)[i].name, "%s", ebuf);
		sprintf(pbuf, "%s/%s", path, ebuf);
		logfile("%s\n", pbuf);
		(*ent)[i].type = ((isdir(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
		
		if(strncmp(path, "/title/00010000", 15) == 0)
		{
			(*ent)[i].function = TYPE_SAVEDATA;
		}
		
		if(strncmp(path, "/title/00010001", 15) == 0)
		{
			(*ent)[i].function = TYPE_TITLE;
		}
		
		if(strncmp(path, "/title/00000001", 15) == 0)
		{
			(*ent)[i].function = TYPE_IOS;
		}
		
		if(strncmp(path, "/title/00010002", 15) == 0)
		{
			(*ent)[i].function = TYPE_SYSTITLE;
		}
		
		if(strncmp(path, "/title/00010004", 15) == 0)
		{
			(*ent)[i].function = TYPE_GAMECHAN;
		}
		
		if(strncmp(path, "/title/00010005", 15) == 0)
		{
			(*ent)[i].function = TYPE_DLC;
		}
		
		if(strncmp(path, "/title/00010008", 15) == 0)
		{
			(*ent)[i].function = TYPE_HIDDEN;
		}
		
		if((strncmp(ebuf, "content", 7) == 0) || (strncmp(ebuf, "data", 4) == 0) || \
			(strstr(path, "content") != 0) || (strstr(path, "data") != 0))
		{
			(*ent)[i].function = TYPE_OTHER;
		}
	}
	
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	free(nbuf);
	return 0;
}

u8 imet[4] = { 0x49, 0x4D, 0x45, 0x54 };
u8 wibn[4] = { 0x57, 0x49, 0x42, 0x4E };
char titlename[64];

char *read_name(u64 titleid, void *magic_word, u32 magic_offset, u32 name_offset, u32 desc_offset, bool get_description)
{
	s32 ret, cfd;
	u32 num, cnt;
	dirent_t *list = NULL;
	char path[ISFS_MAXPATH] ATTRIBUTE_ALIGN(32);
	
	u8 *buffer = allocate_memory(0x150);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\n");
		free(list);
		Unmount_Devices();
		Reboot();
	}
	
	fstats *status = allocate_memory(sizeof(fstats));
	if(status == NULL) 
	{
		//printf("Error allocating memory for status.\n"); 
		logfile("Error allocating memory for status.\n");
		free(list);
		free(buffer);
		Unmount_Devices();
		Reboot();
	}
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	snprintf(titlename, MAX_CHARACTERS(titlename), "Channel/Title deleted from Wii Menu? (couldn't get info)");
	
	ret = getdir_info(path, &list, &num);
	if (ret < 0)
	{
		//printf("Reading folder of the title failed.\n");
		logfile("Reading folder of the title failed.\n");
		free(list);
		free(buffer);
		free(status);
		return titlename;
	}
	
	for(cnt = 0; cnt < num; cnt++)
	{
		if (stricmp(list[cnt].name + strlen(list[cnt].name) - 4, ".app") == 0) 
		{
			memset(buffer, 0x00, 0x150);
			snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content/%s", TITLE_UPPER(titleid), TITLE_LOWER(titleid), list[cnt].name);
			
			cfd = ISFS_Open(path, ISFS_OPEN_READ);
			if (cfd < 0)
			{
				//printf("ISFS_Open for '%s' failed (%d).\n", path, cfd);
				logfile("ISFS_Open for '%s' failed (%d).\n", path, cfd);
				continue;
			}
			
			ret = ISFS_GetFileStats(cfd, status);
			if (ret < 0)
			{
				//printf("\nISFS_GetFileStats(cfd) returned %d.\n", ret);
				logfile("ISFS_GetFileStats(cfd) returned %d.\n", ret);
				ISFS_Close(cfd);
				continue;
			}
			
			if (status->file_length > 0x150)
			{
				ret = ISFS_Read(cfd, buffer, 0x150);
				if (ret < 0)
				{
					//printf("ISFS_Read for '%s' failed (%d).\n", path, ret);
					logfile("ISFS_Read for '%s' failed (%d).\n", path, ret);
					ISFS_Close(cfd);
					continue;
				}
				
				ISFS_Close(cfd);
				
				if (memcmp(&(buffer[magic_offset]), magic_word, 4) == 0)
				{
					free(status);
					
					int i = 0, length = 0;
					
					while (buffer[name_offset + length*2] != 0x00) length++;
					
					char *out = allocate_memory(length+1);
					if(out == NULL)
					{
						//printf("Error allocating memory for title name.\n");
						logfile("Error allocating memory for title name.\n");
						free(list);
						free(buffer);
						Unmount_Devices();
						Reboot();
					}
					
					memset(out, 0x00, length+1);
					
					while (buffer[name_offset + i*2] != 0x00)
					{
						out[i] = (char) buffer[name_offset + i*2];
						i++;
					}
					
					snprintf(titlename, MAX_CHARACTERS(titlename), "%s", out);
					
					if (get_description)
					{
						i = 0;
						length = 0;
						
						while(buffer[desc_offset + length*2] != 0x00) length++;
						
						char *out2 = allocate_memory(length+1);
						if(out2 == NULL)
						{
							//printf("Error allocating memory for title description.\n");
							logfile("Error allocating memory for title description.\n");
							free(list);
							free(buffer);
							free(out);
							Unmount_Devices();
							Reboot();
						}
						
						memset(out2, 0x00, length+1);
						
						while (buffer[desc_offset + i*2] != 0x00)
						{
							out2[i] = (char) buffer[desc_offset + i*2];
							i++;
						}
						
						if ((strlen(out2) != 0) && (strcmp(out2, " ") != 0))
						{
							snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", out, out2);
						}
						
						free(out2);
					}
					
					free(list);
					free(buffer);
					free(out);
					return titlename;
				}
			} else {
				ISFS_Close(cfd);
			}
		}
	}
	
	free(list);
	free(buffer);
	free(status);
	
	return titlename;
}

char *read_name_from_banner_bin(u64 titleid, bool get_description)
{
	s32 cfd, ret;
    char path[ISFS_MAXPATH] ATTRIBUTE_ALIGN(32);
	int i = 0, length = 0;
	
	u8 *buffer = allocate_memory(160);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\n");
		Unmount_Devices();
		Reboot();
	}
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/data/banner.bin", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	snprintf(titlename, MAX_CHARACTERS(titlename), "Channel/Title deleted from Wii Menu? (couldn't get info)");
	
	cfd = ISFS_Open(path, ISFS_OPEN_READ);
	if (cfd < 0)
	{
		//printf("ISFS_Open for '%s' failed (%d).\n", path, cfd);
		logfile("ISFS_Open for '%s' failed (%d).\n", path, cfd);
		return titlename;
	}
	
	ret = ISFS_Read(cfd, buffer, 160);
	if (ret < 0)
	{
		//printf("ISFS_Read for '%s' failed (%d).\n", path, ret);
		logfile("ISFS_Read for '%s' failed (%d).\n", path, ret);
		ISFS_Close(cfd);
		free(buffer);
		return titlename;
	}
	
	ISFS_Close(cfd);	
	
	while(buffer[0x21 + length*2] != 0x00) length++;
	
	char *out = allocate_memory(length+1);
	if(out == NULL)
	{
		//printf("Error allocating memory for banner.bin name.\n");
		logfile("Error allocating memory for banner.bin name.\n");
		free(buffer);
		Unmount_Devices();
		Reboot();
	}
	
	memset(out, 0x00, length+1);
	
	while (buffer[0x21 + i*2] != 0x00)
	{
		out[i] = (char) buffer[0x21 + i*2];
		i++;
	}
	
	snprintf(titlename, MAX_CHARACTERS(titlename), "%s", out);
	
	if (get_description)
	{
		i = 0;
		length = 0;
		
		while(buffer[0x61 + length*2] != 0x00) length++;
		
		char *out2 = allocate_memory(length+1);
		if(out2 == NULL)
		{
			//printf("Error allocating memory for banner.bin description.\n");
			logfile("Error allocating memory for banner.bin description.\n");
			free(buffer);
			free(out);
			Unmount_Devices();
			Reboot();
		}
		
		memset(out2, 0x00, length+1);
		
		while (buffer[0x61 + i*2] != 0x00)
		{
			out2[i] = (char) buffer[0x61 + i*2];
			i++;
		}
		
		if ((strlen(out2) != 0) && (strcmp(out2, " ") != 0))
		{
			snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", out, out2);
		}
		
		free(out2);
	}
	
	free(buffer);
	free(out);
	return titlename;
}

char *get_name(u64 titleid, bool get_description)
{
	char *temp;
	u32 high = TITLE_UPPER(titleid);
	
	if (high == 0x00010000 && TITLE_LOWER(titleid) != 0x48415a41)
	{
		temp = read_name_from_banner_bin(titleid, get_description);
	} else
	if (high == 0x00010005)
	{
		temp = read_name(titleid, wibn, 0x40, 0x61, 0xA1, get_description);
	} else {
		temp = read_name(titleid, imet, 0x80, 0xF1, 0x11B, get_description);
		if (strncmp(temp, "Channel/Title deleted from Wii Menu? (couldn't get info)", 56) == 0)
		{
			temp = read_name_from_banner_bin(titleid, get_description);
		}
	}
	
	return temp;
}

char *read_content_bin_name(FILE *cnt_bin, bool get_description)
{
	int ret;
	static u8 iv[16];
	
	u8 *buf = malloc(0x60);
	if (buf == NULL)
	{
		//printf("\nError allocating memory for buf.\n");
		logfile("\nError allocating memory for buf.\n");
		fclose(cnt_bin);
		Unmount_Devices();
		Reboot();
	}
	
	fseek(cnt_bin, 0xE0, SEEK_SET);
	fread(iv, 16, 1, cnt_bin);
	fread(buf, 0x60, 1, cnt_bin);
	
	ret = aes_128_cbc_decrypt(sd_key, iv, buf, 0x60);
	if (ret < 0)
	{
		//printf("\nError decrypting data.\n");
		logfile("\nError decrypting data.\n");
		free(buf);
		snprintf(titlename, MAX_CHARACTERS(titlename), "Unknown (couldn't get info)");
		return titlename;
	}
	
	int i = 0, length = 0;
	
	while (buf[1 + length*2] != 0x00) length++;
	
	char *out = malloc(length+1);
	if (out == NULL)
	{
		//printf("Error allocating memory for title name.\n");
		logfile("Error allocating memory for title name.\n");
		free(buf);
		fclose(cnt_bin);
		Unmount_Devices();
		Reboot();
	}
	
	memset(out, 0x00, length+1);
	
	while (buf[1 + i*2] != 0x00)
	{
		out[i] = (char) buf[1 + i*2];
		i++;
	}
	
	snprintf(titlename, MAX_CHARACTERS(titlename), "%s", out);
	
	if (get_description)
	{
		i = 0;
		length = 0;
		
		while(buf[0x2B + length*2] != 0x00) length++;
		
		char *out2 = malloc(length+1);
		if (out2 == NULL)
		{
			//printf("Error allocating memory for title description.\n");
			logfile("Error allocating memory for title description.\n");
			free(buf);
			free(out);
			fclose(cnt_bin);
			Unmount_Devices();
			Reboot();
		}
		
		memset(out2, 0x00, length+1);
		
		while (buf[0x2B + i*2] != 0x00)
		{
			out2[i] = (char) buf[0x2B + i*2];
			i++;
		}
		
		if ((strlen(out2) != 0) && (strcmp(out2, " ") != 0))
		{
			snprintf(titlename, MAX_CHARACTERS(titlename), "%s [%s]", out, out2);
		}
		
		free(out2);
	}
	
	free(buf);
	free(out);
	return titlename;
}

u32 pad_data(u8 *ptr, u32 len, bool pad_16)
{
	u32 new_size = (pad_16 ? round16(len) : round64(len));
	
	u32 diff = new_size - len;
	
	if (diff > 0)
	{
		ptr = realloc(ptr, new_size);
		if (ptr != NULL)
		{
			logfile("Memory buffer size reallocated successfully.\n");
			memset(&(ptr[len]), 0x00, diff);
		} else {
			printf("\nError reallocating memory buffer.");
			logfile("Error reallocating memory buffer.");
			free(ptr);
			Unmount_Devices();
			Reboot();
		}
	}
	
	return new_size;
}

s32 read_isfs(char *path, u8 **out, u32 *size)
{
	s32 ret, fd;
	fstats *status;
	
	fd = ISFS_Open(path, ISFS_OPEN_READ);
	if (fd < 0)
	{
		//printf("ISFS_Open for '%s' returned %d.\n", path, fd);
		logfile("ISFS_Open for '%s' returned %d.\n", path, fd);
		return -1;
	}
	
	status = allocate_memory(sizeof(fstats));
	if(status == NULL) 
	{
		//printf("Error allocating memory for status.\n");
		logfile("Error allocating memory for status.\n");
		ISFS_Close(fd);
		Unmount_Devices();
		Reboot();
	}
	
	ret = ISFS_GetFileStats(fd, status);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("ISFS_GetFileStats(fd) returned %d.\n", ret);
		free(status);
		ISFS_Close(fd);
		return -1;
	}
	
	u32 fullsize = status->file_length;
	free(status);
	
	if (fullsize == 0)
	{
		free(status);
		ISFS_Close(fd);
		return -1;
	}
	
	logfile("Size = %u bytes.\n", fullsize);
	
	u8 *out2 = allocate_memory(fullsize);
	if(out2 == NULL) 
	{ 
		//printf("Error allocating memory for out.\n");
		logfile("\nError allocating memory for out.\n");
		ISFS_Close(fd);
		Unmount_Devices();
		Reboot();
	}
	
	u32 blksize, writeindex = 0, restsize = fullsize;
	
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			blksize = BLOCKSIZE;
		} else {
			blksize = restsize;
		}
		
		ret = ISFS_Read(fd, &(out2[writeindex]), blksize);
		if (ret < 0) 
		{
			//printf("\nISFS_Read(%d, %d) returned %d.\n", fd, blksize, ret);
			logfile("\nISFS_Read(%d, %d) returned %d.\n", fd, blksize, ret);
			free(out2);
			ISFS_Close(fd);
			return -1;
		}
		
		writeindex += blksize;
		restsize -= blksize;
	}
	
	ISFS_Close(fd);
	
	*out = out2;
	*size = fullsize;
	return 0;
}

void zero_sig(signed_blob *sig, bool wipe_cid_ecdh)
{
	u8 *sig_ptr = (u8 *)sig;
	memset(sig_ptr + 4, 0, SIGNATURE_SIZE(sig)-4);
	
	/* Wipe Console ID and ECDH data to avoid installation errors on other Wiis */ 
	if (wipe_cid_ecdh)
	{
		memset(sig_ptr + 0x180, 0, 0x3C);
		memset(sig_ptr + 0x1D8, 0, 4);
	}
}

void brute_tmd(tmd *p_tmd)
{
	u16 fill;
	for (fill=0; fill<65535; fill++)
	{
		p_tmd->fill3=fill;
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
	for (fill=0; fill<65535; fill++)
	{
		p_tik->padding=fill;
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
    
void forge_tmd(signed_blob *s_tmd)
{
	printf("Forging TMD signature... ");
	logfile("Forging TMD signature... ");
	zero_sig(s_tmd, false);
	
	brute_tmd(SIGNATURE_PAYLOAD(s_tmd));
}

void forge_tik(signed_blob *s_tik)
{
	printf("Forging Ticket signature... ");
	logfile("Forging Ticket signature... ");
	zero_sig(s_tik, true);
	
	brute_tik(SIGNATURE_PAYLOAD(s_tik));
}

s32 GetTMD(FILE *f, u64 id, signed_blob **tmd, bool forgetmd)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;
	u32 size;
	
	snprintf(path, MAX_CHARACTERS(path), "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(id), TITLE_LOWER(id));
	
	logfile("TMD path is '%s'.\n", path);
	s32 ret = read_isfs(path, &buffer, &size);
	if (ret < 0)
	{
		printf("Error getting TMD!\n");
		return -1;
	}
	
	header->tmd_len = size;
	
	if ((size % 64) != 0)
	{
		size = pad_data(buffer, size, false);
		logfile("Padded TMD size = %u.\n", size);
	}
	
	/* Fakesign TMD if the user chose to */
	if (forgetmd) forge_tmd((signed_blob *)buffer);
	
	/* Write to output WAD */
	fwrite(buffer, 1, size, f);
	
	*tmd = (signed_blob *)buffer;
	
	return 0;
}	

s32 GetTicket(FILE *f, u64 id, signed_blob **tik, bool forgetik)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;
	u32 size;
	
	snprintf(path, MAX_CHARACTERS(path), "/ticket/%08x/%08x.tik", TITLE_UPPER(id), TITLE_LOWER(id));
	
	logfile("Ticket path is '%s'.\n", path);
	s32 ret = read_isfs(path, &buffer, &size);
	if (ret < 0)
	{
		printf("Error getting Ticket!\n");
		return -1;
	}
	
	header->tik_len = size;
	
	if ((size % 64) != 0)
	{
		size = pad_data(buffer, size, false);
		logfile("Padded Ticket size = %u.\n", size);
	}
	
	/* Fakesign ticket if the user chose to */
	if (forgetik) forge_tik((signed_blob *)buffer);
	
	/* Change the common key index to '00' */
	/* Useful to avoid installation errors with WADs dumped from vWii or a Korean Wii */
	if ((buffer[0x1F1] == 0x01) || (buffer[0x1F1] == 0x02)) buffer[0x1F1] = 0x00;
	
	/* Write to output WAD */
	fwrite(buffer, 1, size, f);
	
	*tik = (signed_blob *)buffer;
	
	return 0;
}	

void GetCerts(FILE *f)
{
	if (cert_sys_size != 2560)
	{
		printf("Couldn't get '/sys/cert.sys'. Exiting...");
		logfile("Couldn't get '/sys/cert.sys'. Exiting...");
		Unmount_Devices();
		Reboot();
	}
	
	fwrite(cert_sys, 1, cert_sys_size, f);
	
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
	
	u8 *buffer = (u8*)memalign(32, blksize);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\n");
		ISFS_Close(fd);
		fclose(f);
		Unmount_Devices();
		Reboot();
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

void *GetContentMap(size_t *cm_size)
{
	s32 fd, ret;
	void *buf = NULL;
	fstats *status = allocate_memory(sizeof(fstats));
	logfile("Reading '/shared1/content.map'... ");
	
	fd = ISFS_Open("/shared1/content.map", ISFS_OPEN_READ);
	ret = ISFS_GetFileStats(fd, status);
	
	if (status == NULL || fd < 0 || ret < 0)
	{
		printf("\nError opening '/shared1/content.map' for reading.");
		logfile("\nError opening '/shared1/content.map' for reading.");
		free(status);
		Unmount_Devices();
		Reboot();
	}
	
	*cm_size = status->file_length;
	free(status);
	
	logfile("content.map size = %u bytes.\nWriting '/shared1/content.map' to memory buffer... ", *cm_size);
	buf = allocate_memory(*cm_size);
	if (buf != NULL)
	{
		ISFS_Read(fd, (char*)buf, *cm_size);
		logfile("done.\n\n");
	}
	
	ISFS_Close(fd);
	
	return buf;
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
					fwrite(&(shared_buf[writeindex]), 1, SD_BLOCKSIZE, f);
					restsize = restsize - SD_BLOCKSIZE;
					writeindex = writeindex + SD_BLOCKSIZE;
				} else {
					fwrite(&(shared_buf[writeindex]), 1, restsize, f);
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
		Unmount_Devices();
		Reboot();
	}
	
	printf("done.\n");
	return 0;
}

s32 GetContentFromCntBin(FILE *cnt_bin, FILE *wadout, u16 index, u32 size, u8 *key)
{
	u32 rounded_size = round64(size);
	u32 blksize = SD_BLOCKSIZE; // 32 KB
	
	u8 *buffer = (u8*)memalign(32, blksize);
	if (buffer == NULL)
	{
		//printf("Error allocating memory for buffer.\n");
		logfile("Error allocating memory for buffer.\n");
		fclose(cnt_bin);
		fclose(wadout);
		Unmount_Devices();
		Reboot();
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
	logfile("\n\nGETDIR_DEVICE: path = '%s'.\n", path);
	
	u32 i = 0;
	DIR *dip;
    struct dirent *dit;
	char pbuf[ISFS_MAXPATH + 1];
	
	if ((dip = opendir(path)) == NULL)
    {
        printf("\nError opening '%s'.\n", path);
		logfile("\nError opening '%s'.\n", path);
		sleep(3);
        return -1;
    }
	
    while ((dit = readdir(dip)) != NULL) i++;
	
	rewinddir(dip);
	
	*ent = allocate_memory(sizeof(dirent_t) * i);
	i = 0;
	
	logfile("DEVICE DIR list of '%s':\n\n", path);
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
	
	closedir(dip);
	*cnt = i;
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	return 0;
}

s32 dumpfile(char *source, char *destination)
{
	u8 *buffer;
	fstats *status;

	FILE *file;
	int fd;
	s32 ret;
	u32 size;
	
	fd = ISFS_Open(source, ISFS_OPEN_READ);
	if (fd < 0) 
	{
		//printf("\nError: ISFS_OpenFile for '%s' returned %d.\n", source, fd);
		logfile("\nError: ISFS_OpenFile for '%s' returned %d.\n", source, fd);
		return fd;
	}
	
	if (!create_folders(destination))
	{
		//printf("Error creating folder(s) for '%s'.\n", destination);
		logfile("Error creating folder(s) for '%s'.\n", destination);
		return -1;
	}

	file = fopen(destination, "wb");
	if (!file)
	{
		//printf("\nError: fopen for '%s' returned 0 .\n", destination);
		logfile("\nError: fopen '%s' returned 0.\n", destination);
		ISFS_Close(fd);
		return -1;
	}
	
	status = memalign(32, sizeof(fstats) );
	ret = ISFS_GetFileStats(fd, status);
	if (ret < 0)
	{
		//printf("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		logfile("\nISFS_GetFileStats(fd) returned %d.\n", ret);
		ISFS_Close(fd);
		fclose(file);
		free(status);
		return ret;
	}
	
	Con_ClearLine();
	printf("Dumping file '%s', size = %uKB.", source, (status->file_length / 1024)+1);
	logfile("Dumping file '%s', size = %uKB.", source, (status->file_length / 1024)+1);
	buffer = (u8 *)memalign(32, BLOCKSIZE);
	u32 restsize = status->file_length;
	
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			size = BLOCKSIZE;
		} else
		{
			size = restsize;
		}
		
		ret = ISFS_Read(fd, buffer, size);
		if (ret < 0)
		{
			//printf("\nISFS_Read(%d, %p, %d) returned %d.\n", fd, buffer, size, ret);
			logfile("\nISFS_Read(%d, %p, %d) returned %d.\n", fd, buffer, size, ret);
			ISFS_Close(fd);
			fclose(file);
			free(status);
			free(buffer);
			return ret;
		}
		
		ret = fwrite(buffer, 1, size, file);
		if(ret < 0) 
		{
			//printf("\nfwrite error: %d.\n", ret);
			logfile("\nfwrite error: %d.\n", ret);
			ISFS_Close(fd);
			fclose(file);
			free(status);
			free(buffer);
			return ret;
		}
		
		restsize -= size;
	}
	
	ISFS_Close(fd);
	fclose(file);
	free(status);
	free(buffer);
	return 0;
}

s32 flash(char* source, char* destination)
{
	u8 *buffer3 = (u8 *)memalign(32, BLOCKSIZE);
	if (buffer3 == NULL)
	{
		printf("Out of memory\n");
		return -1;
	}

	s32 ret;
	fstats *stats = memalign(32, sizeof(fstats));
	if (stats == NULL)
	{
		printf("Out of memory\n");
		free(buffer3);
		return -1;
	}

	s32 nandfile;
	FILE *file;
	file = fopen(source, "rb");
	if(!file) 
	{
		printf("fopen error\n");
		logfile("fopen error %s\n", source);
		
		free(stats);
		free(buffer3);
		return -1;
	}
	
	fseek(file, 0, SEEK_END);
	u32 filesize = ftell(file);
	rewind(file);
	printf("Flashing to '%s'.\n", destination);
	logfile("Flashing to '%s'.\n", destination);
	
	printf("%s file size = %u bytes.\n", DEVICE(1), filesize);
	logfile("%s file size = %u bytes.\n", DEVICE(1), filesize);

	ISFS_Delete(destination);
	ISFS_CreateFile(destination, 0, 3, 3, 3);
	nandfile = ISFS_Open(destination, ISFS_OPEN_RW);
	if(nandfile < 0)
	{
		//printf("ISFS_Open (write) error: %d.\n", nandfile);
		logfile("ISFS_Open (write) error: %d.\n", nandfile);
		fclose(file);
		free(stats);
		free(buffer3);
		return -1;
	}
	
	printf("Writing file to NAND...\n");
	
	u32 size;
	u32 restsize = filesize;
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			size = BLOCKSIZE;
		} else {
			size = restsize;
		}
		
		ret = fread(buffer3, 1, size, file);
		if(!ret) 
		{
			//printf("fread error: %d.\n", ret);
			logfile("fread error: %d.\n", ret);
		}
		
		ret = ISFS_Write(nandfile, buffer3, size);
		if(!ret) 
		{
			//printf("ISFS_Write error: %d.\n", ret);
			logfile("ISFS_Write error: %d.\n", ret);
		}
		
		restsize -= size;
	}
	
	ISFS_Close(nandfile);
	nandfile = ISFS_Open(destination, ISFS_OPEN_RW);
	if(nandfile < 0)
	{
		//printf("ISFS_Open (write) error: %d.\n", nandfile);
		logfile("ISFS_Open (write) error: %d.\n", nandfile);
		fclose(file);
		free(stats);
		free(buffer3);
		return -1;
	}	
	
	ret = ISFS_GetFileStats(nandfile, stats);
	printf("Flashing file to NAND successful!\n");
	logfile("Flashing file to nand successful!\n");
	printf("New file is %u bytes.\n", stats->file_length);
	ISFS_Close(nandfile);
	fclose(file);
	free(stats);
	free(buffer3);
	return 0;
}

bool dumpfolder(char source[1024], char destination[1024])
{
	logfile("DUMPFOLDER: source(%s), destination(%s).\n", source, destination);
	
	u32 tcnt;
	s32 ret;
	int i;
	char path[1024];
	char path2[1024];
	char dirpath[1024];
	char fs_dirpath[1024];
	dirent_t *dir = NULL;

	strcpy(dirpath, destination);
	strcpy(fs_dirpath, source);
	ret = getdir_info(fs_dirpath, &dir, &tcnt);
	if(ret == -1)
	{
		//printf("ERROR on getdir!\n");
		logfile("ERROR on getdir!\n");
	}
	
	remove(dirpath);
	
	for(i = 0; i < tcnt; i++) 
	{					
		sprintf(path, "%s/%s", fs_dirpath, dir[i].name);
		logfile("Source file is '%s'.\n", path);
		
		if(dir[i].type == DIRENT_T_FILE) 
		{
			sprintf(path2, "%s/%s", dirpath, dir[i].name);
			logfile("Destination file is '%s'.\n", path2);
			ret = dumpfile(path, path2);
		} else {
			if(dir[i].type == DIRENT_T_DIR) 
			{
				strncat(dirpath, "/", 1);
				strncat(dirpath, dir[i].name, strlen(dir[i].name));
				strncat(fs_dirpath, "/", 1);
				strncat(fs_dirpath, dir[i].name, strlen(dir[i].name));
				remove(dirpath);
				
				if (!dumpfolder(fs_dirpath, dirpath))
				{
					free(dir);
					return false;
				}
			}	
		}
	}
	
	free(dir);
	logfile("Dumping folder '%s' complete.\n", source);
	return true;
}

bool writefolder(char *source, char *temp, char *destination, char *path_out, bool savedata)
{
	logfile("WRITEFOLDER: source(%s), dest(%s).\n", source, destination);
	
	u32 tcnt;
	s32 ret;
	int i;
	bool found = false;
	char path[512];
	char path2[512];
	char dirpath[512];
	char device_dirpath[512];
	char stuff[512];

	dirent_t *dir = NULL;

	strcpy(dirpath, destination);
	strcpy(device_dirpath, source);
	if(savedata != true)
	{
		dirent_t *temp_dir = NULL;
		ret = getdir_device(device_dirpath, &temp_dir, &tcnt);
		if(ret < 0)
		{
			//printf("ERROR on getdir_device!\n");
			logfile("ERROR on getdir_device!\n");
		}	
		
		for(i = 0; i < tcnt; i++) 
		{	
			if(strncmp(temp_dir[i].name + 5, temp, 4) == 0)
			{
				logfile("Savedata found: '%s'.\n", temp_dir[i].name);
				sprintf(device_dirpath, "%s/%s", source, temp_dir[i].name);
				free(temp_dir);
				tcnt = 0;
				ret = getdir_device(device_dirpath, &dir, &tcnt);
				if(ret < 0)
				{
					//printf("ERROR on getdir_device!\n");
					logfile("ERROR on getdir_device!\n");
				}	
				
				found = true;
				strcpy(stuff, device_dirpath);
				//path_out = allocate_memory(strlen(stuff) + 10);
				//memset(path_out, 0, strlen(stuff) + 10);
				sprintf(path_out, "%s", stuff);
				break;
			}	
		}
	} else {
		found = true;
		strcpy(stuff, device_dirpath);
		ret = getdir_device(device_dirpath, &dir, &tcnt);
		if(ret < 0)
		{
			//printf("ERROR on getdir_device!\n");
			logfile("ERROR on getdir_device!\n");
		}	
	}
	
	if(found != true)
	{
		printf("Couldn't find the savedata on the %s! Please extract the savedata first.\n", (isSD ? "SD card" : "USB storage"));
		logfile("Couldn't find the savedata on the %s!\n", (isSD ? "SD card" : "USB storage"));
		sleep(3);
		free(dir);
		return false;
	}
	
	if(isdir(dirpath) == 0)
	{
		//Need to fix recursive stuff i think ...
		ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
		logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
	} else {
		ret = ISFS_Delete(dirpath);
		logfile("ISFS_Delete(%s); %d\n", dirpath, ret);
		ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
		logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
	}
	
	for(i = 0; i < tcnt; i++) 
	{				
		sprintf(path, "%s/%s", stuff, dir[i].name);
		logfile("Source file is '%s'.\n", path);
		
		if(dir[i].type == DIRENT_T_FILE) 
		{
			sprintf(path2, "%s/%s", destination, dir[i].name);
			logfile("Destination file is '%s'.\n", path2);
			ret = flash(path, path2);
		} else {
			if(dir[i].type == DIRENT_T_DIR) 
			{
				strncat(dirpath, "/", 1);
				strncat(dirpath, dir[i].name, strlen(dir[i].name));
				strncat(device_dirpath, "/", 1);
				strncat(device_dirpath, dir[i].name, strlen(dir[i].name));
				//ISFS_Delete(dirpath);
				//ISFS_CreateDir(dirpath, 0, 3, 3, 3);
				if(isdir(dirpath) == 0)
				{
					//Need to fix recursive stuff i think ...
					ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
					logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
				} else {
					ret = ISFS_Delete(dirpath);
					logfile("ISFS_Delete(%s); %d\n", dirpath, ret);
					ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
					logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
				}
				
				char *random_buffer;
				random_buffer = allocate_memory(256);
				memset(random_buffer, 0, 256);
				if (!writefolder(device_dirpath, temp, dirpath, random_buffer, true))
				{
					free(dir);
					return false;
				}
				free(random_buffer);
			}	
		}
	}
	
	free(dir);
	logfile("Writing folder '%s' complete.\n", source);
	return true;
}

char *RemoveIllegalCharacters(char *name)
{
	u32 i, len = strlen(name);
	for (i = 0; i < len; i++)
	{
		if (memchr("?[]/\\=+<>:;\",*|^", name[i], sizeof("?[]/\\=+<>:;\",*|^")-1)) name[i] = '_';
	}
	return name;
}

bool extract_savedata(u64 titleID)
{
	char path[ISFS_MAXPATH];
	char device_path[MAXPATHLEN];
	char *temp;
	u32 low = TITLE_LOWER(titleID);
	bool success = false;
	logfile("Extracting title %08x-%08x...\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	temp = allocate_memory(6);
	memset(temp, 0, 6);
	memcpy(temp, (char *)(&low), 4);
	logfile("ID = %s.\n", temp);
	sprintf(path, "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS path is '%s'.\n", path);
	
	if(TITLE_UPPER(titleID) == 0x00010000)
	{
		//sprintf(device_path, "%s:/YABDM/Savedata/DISC %s", DEVICE(0), temp);
		sprintf(device_path, "%s:/YABDM/Savedata/DISC %s - %s", DEVICE(0), temp, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: disc-based game.\n");
	} else
	if(TITLE_UPPER(titleID) == 0x00010001)
	{
		//sprintf(device_path, "%s:/YABDM/Savedata/CHAN %s", DEVICE(0), temp);
		sprintf(device_path, "%s:/YABDM/Savedata/CHAN %s - %s", DEVICE(0), temp, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: downloaded channel title.\n");
	} else
	if(TITLE_UPPER(titleID) == 0x00010004)
	{
		//sprintf(device_path, "%s:/YABDM/Savedata/CHSV %s", DEVICE(0), temp);
		sprintf(device_path, "%s:/YABDM/Savedata/CHSV %s - %s", DEVICE(0), temp, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: game that uses channel.\n");
	}
	
	logfile("%s path is '%s'.\n", DEVICE(1), device_path);
	success = dumpfolder(path, device_path);
	
	/* Dump the title.tmd file */
	sprintf(path, "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	strcat(device_path, "/title.tmd");
	logfile("path = %s.\n", path);
	logfile("device_path = %s.\n", device_path);
	dumpfile(path, device_path);
	return success;
}	

bool install_savedata(u64 titleID)
{
	char path[ISFS_MAXPATH];
	char device_path[MAXPATHLEN];
	char path_out[1024];
	char *temp;
	s32 ret;
	u32 low = TITLE_LOWER(titleID);
	bool success = false;
	logfile("Installing title %08x-%08x...\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	temp = allocate_memory(6);
	memset(temp, 0, 6);
	memcpy(temp, (char *)(&low), 4);
	logfile("ID = %s.\n", temp);
	sprintf(path, "/title/%08x/%08x", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	
	if(isdir(path) == 0)
	{
		ret = ISFS_CreateDir(path, 0, 3, 3, 3);
		logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", path, ret);
	}
	
	sprintf(path, "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS path is '%s'.\n", path);
	
	sprintf(device_path, "%s:/YABDM/Savedata", DEVICE(0));
	logfile("%s path is '%s'.\n", DEVICE(1), device_path);
	
	success = writefolder(device_path, temp, path, path_out, false);
	sprintf(path, "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	strcat(path_out, "/title.tmd");
	logfile("path_out = %s.\n", path_out);
	logfile("path = %s.\n", path);
	flash(path_out, path);
	return success;
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
			return "v4.3J";
		case 513:
			return "v4.3U";
		case 514:
			return "v4.3E";
		case 518:
			return "v4.3K";
		default:
			return "(Unknown Version)";
	}
}

char ascii_id[5];
bool ascii = false;

char *GetASCII(u32 name)
{
	snprintf(ascii_id, MAX_CHARACTERS(ascii_id), "%s", (char *)(&name));
	return ascii_id;
}

void browser(char cpath[ISFS_MAXPATH + 1], dirent_t* ent, int cline, int lcnt)
{
	int i;
	resetscreen();
	printheadline();
	
	logfile("\n\nBROWSER: Using Wii NAND. Inserted device: %s.\nPath: %s\n", (isSD ? "SD Card" : "USB Storage"), cpath);
	
	printf("[1/Y] Dump Options  [A] Confirm/Enter Directory  [2/X] Change view mode\n");
	printf("[B] Cancel/Return to Parent Directory  [Home/Start] Exit\n");
	printf("[+/R] Switch to content.bin conversion\n\n");
	
	printf("Path: %s\n\n", cpath);
	
	if (lcnt == 0)
	{
		printf("No files/directories found!");
		printf("\nPress B to go back to the previous dir.");
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
}

void make_header(void)
{
	wadHeader *now = allocate_memory(sizeof(wadHeader));
	if(now == NULL) 
	{
		//printf("Error allocating memory for wadheader.\n");
		logfile("Error allocating memory for wadheader.\n");
		Unmount_Devices();
		Reboot();
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

void get_title_key(signed_blob *s_tik, u8 *key)
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
		free(s_tik);
		Unmount_Devices();
		Reboot();
	}
	
	memcpy(key, keyout, sizeof(keyout));
	logfile("\nDecrypted Title Key = ");
	hex_key_dump(keyout, sizeof(keyout));
	logfile("\n");
}

s32 Wad_Dump(u64 id, char *path, bool ftik, bool ftmd)
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
		Unmount_Devices();
		Reboot();
	}
	memset(padding_table, 0, 64);
	fwrite(padding_table, 1, 64, wadout);
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
	ret = GetTicket(wadout, id, &p_tik, ftik);
	if (ret < 0)
	{
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
	ret = GetTMD(wadout, id, &p_tmd, ftmd);
	if (ret < 0)
	{
		free(header);
		free(p_tik);
		fclose(wadout);
		remove(path);
		return -1;
	}
	printf("done.\n");
	logfile("done.\n");
	
	/* Get Title Key */
	printf("Decrypting AES Title Key... ");
	logfile("Decrypting AES Title Key... ");
	get_title_key(p_tik, (u8 *)key);
	printf("done.\n");
	logfile("done.\n");
	free(p_tik);
	
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
				ret = GetContent(wadout, id, content->cid, (u8*)key, content->index, (u32)content->size);
				break;
			case 0x8001: // Shared
				ret = GetSharedContent(wadout, (u8*)key, content->index, content->hash, cm, content_map_items);
				break;
			case 0x4001: // DLC
				ret = GetContent(wadout, id, content->cid, (u8*)key, content->index, (u32)content->size);
				break;
			default:
				printf("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
				logfile("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
				free(header);
				free(p_tmd);
				fclose(wadout);
				remove(path);
				Unmount_Devices();
				Reboot();
				break;
		}
		
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
	u8 *footer_buf;
	u32 footer_size;
	printf("Adding footer... ");
	logfile("Adding footer... ");
	read_isfs(footer_path, &footer_buf, &footer_size);
	header->footer_len = footer_size;
	if ((footer_size % 64) != 0) footer_size = pad_data(footer_buf, footer_size, false);
	fwrite(footer_buf, 1, footer_size, wadout);
	free(footer_buf);
	printf("done.\n");
	logfile("done.\n");
	
	/* Add WAD header */
	printf("Writing header info... ");
	logfile("Writing header info... ");
	rewind(wadout);
	fwrite((u8 *)header, 1, 0x20, wadout);
	printf("done.\n");
	logfile("done.\nHeader hexdump:\n");
	hexdump_log(header, 0x20);
	
	free(header);
	fclose(wadout);
	return 0;
}

s32 Content_bin_Dump(FILE *cnt_bin, char* path, bool ftik, bool ftmd)
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
		Unmount_Devices();
		Reboot();
	}
	memset(padding_table, 0, 64);
	fwrite(padding_table, 1, 64, wadout);
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
		Get_OTP_data();
		printf("done.\n");
		logfile("done.\n");
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
		Unmount_Devices();
		Reboot();
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
		Unmount_Devices();
		Reboot();
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
	
	if (ftmd) forge_tmd((signed_blob *)tmd_buf);
	p_tmd = (signed_blob *)tmd_buf;
	
	printf("done.\n");
	logfile("done.\n");
	
	/* Get Ticket */
	printf("Reading Ticket... ");
	logfile("Reading Ticket... ");
	ret = GetTicket(wadout, titleID, &p_tik, ftik);
	if (ret < 0)
	{
		free(header);
		fclose(wadout);
		remove(path);
		return -1;
	}
	printf("done.\n");
	logfile("done.\n");
	
	/* Get Title Key */
	printf("Decrypting AES Title Key... ");
	logfile("Decrypting AES Title Key... ");
	get_title_key(p_tik, (u8 *)key);
	printf("done.\n");
	logfile("done.\n");
	free(p_tik);
	
	/* Now we can write the TMD data */
	fwrite(p_tmd, 1, tmd_size, wadout);
	
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
				printf("Adding regular content %08x... ", content->cid);
				ret = GetContentFromCntBin(cnt_bin, wadout, content->index, (u32)content->size, (u8*)key);
				break;
			case 0x8001: // Shared, they don't get included in the content.bin file
				ret = GetSharedContent(wadout, (u8*)key, content->index, content->hash, cm, content_map_items);
				break;
			case 0x4001: // DLC, I'm not sure if this type of content gets included or not, but let's be on the safe side
				printf("Adding regular content %08x... ", content->cid);
				ret = GetContentFromCntBin(cnt_bin, wadout, content->index, (u32)content->size, (u8*)key);
				break;
			default:
				printf("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
				logfile("Unknown content type: 0x%04x. Aborting mission...\n", content->type);
				free(header);
				free(p_tmd);
				fclose(cnt_bin);
				fclose(wadout);
				remove(path);
				Unmount_Devices();
				Reboot();
				break;
		}
		
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
		Unmount_Devices();
		Reboot();
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
	
	if ((header->footer_len % 64) != 0)
	{
		memset(&(footer_buf[header->footer_len]), 0x00, (footer_size - header->footer_len));
	}
	
	fwrite(footer_buf, footer_size, 1, wadout);
	free(footer_buf);
	
	printf("done.\n");
	logfile("done.\n");
	
	/* Add WAD header */
	printf("Writing header info... ");
	logfile("Writing header info... ");
	rewind(wadout);
	fwrite((u8 *)header, 1, 0x20, wadout);
	printf("done.\n");
	logfile("done.\nHeader hexdump:\n");
	hexdump_log(header, 0x20);
	
	free(header);
	fclose(wadout);
	
	return 0;
}

u64 copy_id(char *path)
{
	logfile("COPY_ID: path = %s.\n", path);
	char *low_out = allocate_memory(10);
	memset(low_out, 0, 10);
	char *high_out = allocate_memory(10);
	memset(high_out, 0, 10);	
	
	strncpy(high_out, path+7, 8);
	strncpy(low_out, path+16, 8);

	u64 titleID = TITLE_ID(strtol(high_out, NULL, 16), strtol(low_out,NULL,16));
	logfile("Generated copy_id ID was '%08x-%08x'.\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	free(low_out);
	free(high_out);
	return titleID;
}

bool for_tik = false;
bool for_tmd = false;

void select_forge()
{
	u32 pressed;

	printf("\n\nDo you want to fakesign the ticket?");
	printf("\n[A] Yes (recommended)   [B] No\n");
	
	while(true)
	{
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		if (pressed & WPAD_BUTTON_A)
		{
			for_tik = true;
			logfile("forge_tik set to true.\n");
			break;
		}
		
		if (pressed & WPAD_BUTTON_B)
		{
			for_tik = false;
			logfile("forge_tik set to false.\n");
			break;
		}
	}
	
	printf("\nDo you want to fakesign the TMD?");
	printf("\n[A] Yes    [B] No (recommended)\n");
	
	while(true)
	{
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		if (pressed & WPAD_BUTTON_A)
		{
			for_tmd = true;
			logfile("forge_tmd set to true.\n");
			break;
		}
		
		if (pressed & WPAD_BUTTON_B)
		{
			for_tmd = false;
			logfile("forge_tmd set to false.\n");
			break;
		}
	}
}

void dump_menu(char *cpath, char *tmp, int cline, dirent_t *ent)
{
	u32 pressed;
	u64 titleID;
	
	char *options[3] = { "Backup Savedata >", "< Restore Savedata >" , "< Backup to WAD"};
	int selection = 0;
	
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
	
	logfile("cline: %s.\n", some);
	switch(selection)
	{
		case 0: // Backup savedata
			if ((ent[cline].function == TYPE_SAVEDATA && strncmp(ent[cline].name, "48415a41", 8) != 0) || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
			{
				printf("\n\nBacking up savedata... \n");
				logfile("Backing up savedata... \n");
				titleID = copy_id(some);
				extract_savedata(titleID);
				printf("done .\n");
				logfile("done.\n");
			} else {
				printf("\n\nThe title you chose has no savedata!\n");
				printf("Use the WAD function for this.");
			}
			break;
		case 1: // Restore savedata
			if ((ent[cline].function == TYPE_SAVEDATA && strncmp(ent[cline].name, "48415a41", 8) != 0) || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
			{
				printf("\n\nRestoring savedata... \n");
				logfile("Restoring savedata... \n");
				titleID = copy_id(some);
				install_savedata(titleID);
				printf("done.\n");
				logfile("done.\n");
			} else {
				printf("\n\nThe title you chose has no savedata!\n");
				printf("Use the WAD function for this.");
			}
			break;	
		case 2: // Backup to WAD
			/* Workaround for HAZA (00010000-48415a41) */
			/* This title is responsible for changing the Photo Channel v1.0 placeholder data in the System Menu to the v1.1 */
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
					if (strncmp(ent[cline].titlename, "Unknown Hidden Channel", 22) == 0)
					{
						snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/00010008-%s v%u", DEVICE(0), GetASCII(low), get_version(titleID));
					} else {
						snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/%s", DEVICE(0), ent[cline].titlename);
					}
				}
				
				if (for_tik && for_tmd)
				{
					strncat(dump_path, " (ftmd+ftik).wad", 16);
				} else
				if (!for_tik && for_tmd)
				{
					strncat(dump_path, " (ftmd).wad", 11);
				} else
				if (for_tik && !for_tmd)
				{
					strncat(dump_path, " (ftik).wad", 11);
				} else {
					strncat(dump_path, ".wad", 4);
				}
				
				s32 ret = Wad_Dump(titleID, dump_path, for_tik, for_tmd);
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
	
	sleep(3);
}

void sd_browser_ent_info(dirent_t* ent, int cline, int lcnt)
{
	int i;
	resetscreen();
	printheadline();
	
	logfile("\n\nSD_BROWSER: Using SD card. Inserted device: %s.\nPath: %s\n", (isSD ? "SD Card" : "USB Storage"), SD_ROOT_DIR);
	
	printf("[A] Convert selected title's content.bin file to WAD  [Home/Start] Exit\n");
	printf("[+/R] Return to the main browser screen\n\n");
	
	printf("Path: %s\n\n", SD_ROOT_DIR);
	
	for (i = (cline / 15)*15; i < lcnt && i < (cline / 15)*15+15; i++)
	{
		printf("%s %-12s - %s\n", (i == cline ? ARROW : "  "), ent[i].name, ent[i].titlename);
	}
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
		return;
	}
	
	char dump_path[100];
	snprintf(dump_path, MAX_CHARACTERS(dump_path), "%s:/YABDM/WAD/%s - %.4s (content.bin)", DEVICE(0), RemoveIllegalCharacters(read_content_bin_name(cnt_bin, false)), cnt_path+22);
	rewind(cnt_bin);
	
	if (for_tik && for_tmd)
	{
		strncat(dump_path, " (ftmd+ftik).wad", 16);
	} else
	if (!for_tik && for_tmd)
	{
		strncat(dump_path, " (ftmd).wad", 11);
	} else
	if (for_tik && !for_tmd)
	{
		strncat(dump_path, " (ftik).wad", 11);
	} else {
		strncat(dump_path, ".wad", 4);
	}
	
	s32 ret = Content_bin_Dump(cnt_bin, dump_path, for_tik, for_tmd);
	if (ret < 0)
	{
		printf("\nError dumping title to WAD file!");
	} else {
		logfile("WAD dump complete!\n");
		printf("WAD dump complete! Output file:\n\n\t%s", dump_path);
	}
	
	fclose(cnt_bin);
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
		return;
	}
	
	if (lcnt == 0)
	{
		printf("No files/directories found in '%s'!", SD_ROOT_DIR);
		if (ent) free(ent);
		sleep(3);
		return;
	}
	
	printf("Loading title names, please wait...");
	
	FILE *f;
	
	/* Create name list - Speeds up directory browsing */
	for (i = 0; i < lcnt; i++)
	{
		if (ent[i].type == DIRENT_T_DIR)
		{
			snprintf(tmp, MAX_CHARACTERS(tmp), "%s/%s/content.bin", SD_ROOT_DIR, ent[i].name);
			f = fopen(tmp, "rb");
			if (f)
			{
				snprintf(ent[i].titlename, MAX_CHARACTERS(ent[i].titlename), "%s", read_content_bin_name(f, true));
				fclose(f);
			} else {
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
			if (ent[cline].type == DIRENT_T_DIR)
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
			free(cm);
			free(ent);
			Unmount_Devices();
			Reboot();
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
	logfile("Using IOS%u v%u.\n\n", IOS_GetVersion(), IOS_GetRevision());
	
	/* Read the content.map file here to avoid reading it at a later time */
	cm = (map_entry_t*)GetContentMap(&content_map_size);
	if(cm == NULL || content_map_size == 0)
	{
		printf("\n\nError loading '/shared1/content.map', size = 0.");
		logfile("\nError loading '/shared1/content.map', size = 0.");
		Unmount_Devices();
		Reboot();
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
			if(ent[cline].type == DIRENT_T_DIR)
			{
				strcpy(tmp, cpath);
				if(strcmp(cpath, "/") != 0)
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
			free(cm);
			free(ent);
			break;
		}
	}
	
	printf("\nExiting...");
	
	/* End of app loop */
}
