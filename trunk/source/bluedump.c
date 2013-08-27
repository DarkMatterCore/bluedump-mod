/*******************************************************************************
 * bluedump.c                                                                  *
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

#include "tools.h"
#include "rijndael.h"
#include "sha1.h"
#include "../build/cert_sys.h"

#define BLOCKSIZE		0x4000 // 16 KB
#define SD_BLOCKSIZE	0x8000 // 32 KB

#define DIRENT_T_FILE 0
#define DIRENT_T_DIR 1

#define ROOT_DIR "/title"
#define DEVICE(x) ((x == 0) ? (isSD ? "sd" : "usb") : (isSD ? "SD" : "USB"))

#define TYPE_SAVEDATA 	0
#define TYPE_TITLE 		1
#define TYPE_IOS		2
#define TYPE_SYSTITLE	3
#define TYPE_GAMECHAN	4
#define TYPE_DLC		5
#define TYPE_HIDDEN		6
#define TYPE_OTHER 		7

#define TITLE_UPPER(x)		((u32)((x) >> 32))
#define TITLE_LOWER(x)		((u32)(x))
#define TITLE_ID(x,y)		(((u64)(x) << 32) | (y))

#define round_up(x,n)   (-(-(x) & -(n)))
#define round64(x)      round_up(x,0x40)
#define round16(x)		round_up(x,0x10)

u8 commonkey[16] = { 0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7 };

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
// Example: Input "sd:/BlueDump/00000001/test.bin" creates "sd:/BlueDump" and "sd:/BlueDump/00000001"
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

typedef struct _dirent
{
	char name[ISFS_MAXPATH + 1];
	u16 version;
	int type;
	int function;
	u32 ownerID;
	u16 groupID;
	u8 attributes;
	u8 ownerperm;
	u8 groupperm;
	u8 otherperm;
} dirent_t;	

/* 'WAD Header' structure */
typedef struct 
{
	/* Header length */
	u32 header_len;

	/* WAD type */
	u16 type;

	u16 padding;

	/* Data length */
	u32 certs_len;
	u32 crl_len;
	u32 tik_len;
	u32 tmd_len;
	u32 data_len;
	u32 footer_len;
} ATTRIBUTE_PACKED wadHeader;

wadHeader *header;

void *allocate_memory(u32 size)
{
	return memalign(32, (size+63)&(~63));
}

typedef struct map_entry
{
	char filename[8];
	u8 sha1[20];
} __attribute__((packed)) map_entry_t;

map_entry_t *cm;
size_t content_map_size;
size_t content_map_items;

void check_not_0(size_t ret, char *error)
{
	if(ret <= 0)
	{
		printf(error);
		logfile(error);
		Unmount_Devices();
		Reboot();
	}	
}

s32 __FileCmp(const void *a, const void *b)
{
	dirent_t *hdr1 = (dirent_t *)a;
	dirent_t *hdr2 = (dirent_t *)b;
	
	if (hdr1->type == hdr2->type)
	{
		return strcmp(hdr1->name, hdr2->name);
	} else
	{
		if (hdr1->type == DIRENT_T_DIR)
		{
			return -1;
		} else
		{
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
	char buffer[256];
	s32 cfd;
	s32 ret;
	u16 version;
	u8 *tmdbuf = (u8*)memalign(32, 1024);
	
	sprintf(buffer, "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	
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
	logfile("version = %u\n",version);
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
	*ent = allocate_memory(sizeof(dirent_t) * num);
	logfile("\nISFS DIR list of %s: \n\n", path);
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

u8 imet[4] = {0x49, 0x4D, 0x45, 0x54};
u8 wibn[4] = {0x57, 0x49, 0x42, 0x4E};

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
	
	sprintf(path, "/title/%08x/%08x/content", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	
	ret = getdir_info(path, &list, &num);
	if (ret < 0)
	{
		//printf("Reading folder of the title failed.\n");
		logfile("Reading folder of the title failed.\n");
		free(list);
		free(buffer);
		free(status);
		return NULL;
	}
	
	for(cnt = 0; cnt < num; cnt++)
	{        
		if (stricmp(list[cnt].name + strlen(list[cnt].name) - 4, ".app") == 0) 
		{
			memset(buffer, 0x00, 0x150);
			sprintf(path, "/title/%08x/%08x/content/%s", TITLE_UPPER(titleid), TITLE_LOWER(titleid), list[cnt].name);
			
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
					
					while (buffer[name_offset + i*2] != 0x00) i++;
					
					length = i;
					i = 0;
					
					char *out;
					
					if (get_description)
					{
						out = allocate_memory(length+40);
					} else {
						out = allocate_memory(length+1);
					}
					
					if(out == NULL)
					{
						//printf("Error allocating memory for title name.\n");
						logfile("Error allocating memory for title name.\n");
						free(list);
						free(buffer);
						Unmount_Devices();
						Reboot();
					}
					
					memset(out, 0x00, (get_description ? length+40 : length+1));
					
					while (buffer[name_offset + i*2] != 0x00)
					{
						out[i] = (char) buffer[name_offset + i*2];
						i++;
					}
					
					if (get_description)
					{
						i = 0;
						length = 0;
						
						while(buffer[desc_offset + i*2] != 0x00) i++;
						
						length = i;
						i = 0;
						
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
							strcat(out, " [");
							strcat(out, out2);
							strcat(out, "]");
						}
						
						free(out2);
					}
					
					free(list);
					free(buffer);
					return out;
				}
			} else {
				ISFS_Close(cfd);
			}
		}
	}
	
	free(list);
	free(buffer);
	free(status);
	
	return NULL;
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
	
	sprintf(path, "/title/%08x/%08x/data/banner.bin", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	
	cfd = ISFS_Open(path, ISFS_OPEN_READ);
	if (cfd < 0)
	{
		//printf("ISFS_Open for '%s' failed (%d).\n", path, cfd);
		logfile("ISFS_Open for '%s' failed (%d).\n", path, cfd);
		return NULL;
	}
	
	ret = ISFS_Read(cfd, buffer, 160);
	if (ret < 0)
	{
		//printf("ISFS_Read for '%s' failed (%d).\n", path, ret);
		logfile("ISFS_Read for '%s' failed (%d).\n", path, ret);
		ISFS_Close(cfd);
		free(buffer);
		return NULL;
	}
	
	ISFS_Close(cfd);	
	
	while(buffer[0x21 + i*2] != 0x00) i++;
	
	length = i;
	i = 0;
	
	u32 size = (get_description ? length+40 : length+1);
	char *out = allocate_memory(size);
	if(out == NULL)
	{
		//printf("Error allocating memory for banner.bin name.\n");
		logfile("Error allocating memory for banner.bin name.\n");
		free(buffer);
		Unmount_Devices();
		Reboot();
	}
	
	memset(out, 0x00, size);
	
	while (buffer[0x21 + i*2] != 0x00)
	{
		out[i] = (char) buffer[0x21 + i*2];
		i++;
	}
	
	if (get_description)
	{
		i = 0;
		length = 0;
		
		while(buffer[0x61 + i*2] != 0x00) i++;
		
		length = i;
		i = 0;
		
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
			strcat(out, " [");
			strcat(out, out2);
			strcat(out, "]");
		}
		
		free(out2);
	}
	
	free(buffer);
	return out;
}

char *get_name(u64 titleid, bool get_description)
{
	char *temp;
	u32 high = TITLE_UPPER(titleid);
	
	if (high == 0x00010000)
	{
		temp = read_name_from_banner_bin(titleid, get_description);
	} else
	if (high == 0x00010005)
	{
		temp = read_name(titleid, wibn, 0x40, 0x61, 0xA1, get_description);
	} else {
		temp = read_name(titleid, imet, 0x80, 0xF1, 0x11B, get_description);
		if (temp == NULL)
		{
			temp = read_name_from_banner_bin(titleid, get_description);
		}
	}
	
	if (temp == NULL)
	{
		temp = allocate_memory(2);
		sprintf(temp, "Channel/Title deleted from Wii Menu? (couldn't get info)");
	}
	
	return temp;
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

u32 read_isfs(char *path, u8 **out)
{
	u32 size;
	s32 ret, fd;
	fstats *status;
	
	fd = ISFS_Open(path, ISFS_OPEN_READ);
	if (fd < 0)
	{
		//printf("ISFS_Open for '%s' returned %d.\n", path, fd);
		logfile("ISFS_Open for '%s' returned %d.\n", path, fd);
		Unmount_Devices();
		Reboot();
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
		ISFS_Close(fd);
		free(status);
		Unmount_Devices();
		Reboot();
	}
	
	u32 fullsize = status->file_length;
	logfile("Size = %u bytes.\n", fullsize);
	
	u8 *out2 = allocate_memory(fullsize);
	if(out2 == NULL) 
	{ 
		//printf("Error allocating memory for out.\n");
		logfile("\nError allocating memory for out.\n");
		free(status);
		ISFS_Close(fd);
		Unmount_Devices();
		Reboot();
	}
	
	u32 writeindex = 0, restsize = status->file_length;
	
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			size = BLOCKSIZE;
		} else {
			size = restsize;
		}
		
		ret = ISFS_Read(fd, &(out2[writeindex]), size);
		if (ret < 0)
		{
			//printf("\nISFS_Read(%d, %d) returned %d.\n", fd, size, ret);
			logfile("\nISFS_Read(%d, %d) returned %d.\n", fd, size, ret);
			free(status);
			Unmount_Devices();
			Reboot();
		}
		
		writeindex += size;
		restsize -= size;
	}
	
	free(status);
	ISFS_Close(fd);
	*out = out2;
	return fullsize;
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

void GetTMD(FILE *f, u64 id, signed_blob **tmd, bool forgetmd)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;
	
	u32 size;
	
	sprintf(path, "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(id), TITLE_LOWER(id));
	
	logfile("TMD path is '%s'.\n", path);
	size = read_isfs(path, &buffer);
	header->tmd_len = size;
	
	if ((size % 64) != 0)
	{
		size = pad_data(buffer, size, false);
		logfile("Padded TMD size = %u.\n", size);
	}
	
	/* Fakesign TMD if the user chose to */
	if (forgetmd)
	{
		forge_tmd((signed_blob *)buffer);
	}
	
	/* Write to output WAD */
	fwrite(buffer, 1, size, f);
	
	*tmd = (signed_blob *)buffer;
}	

void GetTicket(FILE *f, u64 id, signed_blob **tik, bool forgetik)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;
	
	u32 size;
	
	sprintf(path, "/ticket/%08x/%08x.tik", TITLE_UPPER(id), TITLE_LOWER(id));
	
	logfile("Ticket path is '%s'.\n", path);
	size = read_isfs(path, &buffer);
	header->tik_len = size;
	
	if ((size % 64) != 0)
	{
		size = pad_data(buffer, size, false);
		logfile("Padded Ticket size = %u.\n", size);
	}
	
	/* Fakesign ticket if the user chose to */
	if (forgetik)
	{
		forge_tik((signed_blob *)buffer);
	}
	
	/* Change the common key index to '00' */
	/* Useful to avoid installation errors with WADs dumped from vWii or a Korean Wii */
	if ((buffer[0x1F1] == 0x01) || (buffer[0x1F1] == 0x02))
	{
		buffer[0x1F1] = 0x00;
	}
	
	/* Write to output WAD */
	fwrite(buffer, 1, size, f);
	
	*tik = (signed_blob *)buffer;
}	

u32 GetCerts(FILE *f)
{
	if (cert_sys_size != 2560)
	{
		printf("Couldn't get '/sys/cert.sys'. Exiting...");
		logfile("Couldn't get '/sys/cert.sys'. Exiting...");
		Unmount_Devices();
		Reboot();
	}
	
	fwrite(cert_sys, 1, cert_sys_size, f);
	
	return cert_sys_size;
}

u32 GetContent(FILE *f, u64 id, u16 content, u16 index, u32 size)
{
	char path[ISFS_MAXPATH];
	
	sprintf(path, "/title/%08x/%08x/content/%08x.app", TITLE_UPPER(id), TITLE_LOWER(id), content);
	logfile("Regular content path is '%s'.\n", path);
	printf("Adding regular content %08x.app... ", content);
	
	s32 fd = ISFS_Open(path, ISFS_OPEN_READ);
	if (fd < 0)
	{
		//printf("ISFS_Open for '%s' returned %d.\n", path, fd);
		logfile("ISFS_Open for '%s' returned %d.\n", path, fd);
		return 0;
	}
	
	u32 blksize = BLOCKSIZE; // 16KB
	
	u8 *buffer = (u8*)memalign(32, blksize);
	if (buffer == NULL)
	{
		//printf("Allocating memory for buffer failed.\n");
		logfile("Allocating memory for buffer failed.\n");
		ISFS_Close(fd);
		Unmount_Devices();
		Reboot();
	}
	
	u8 *encryptedcontentbuf = (u8*)memalign(32, blksize);
	if (encryptedcontentbuf == NULL)
	{
		//printf("Allocating memory for buffer failed.\n");
		logfile("Allocating memory for encryptedcontentbuf failed.\n");
		ISFS_Close(fd);
		Unmount_Devices();
		Reboot();
	}
	
	s32 ret = 0;
	u32 i, pad, size2 = 0;
	
	static u8 iv[16];
	memset(iv, 0, 16);
	memcpy(iv, &index, 2);
	
	logfile("Writing...\n");
	for (i = 0; i < size; i += blksize)
	{
		if (blksize > size - i)
		{
			blksize = size - i;
		}
		
		ret = ISFS_Read(fd, buffer, blksize);
		if (ret < 0) break;
		
		/* Pad data to a 16-byte boundary (required for the encryption process). Probably only needed for the last chunk */
		if ((blksize % 16) != 0)
		{
			pad = 16 - blksize % 16;
			memset(&(buffer[blksize]), 0x00, pad);
			logfile("Content chunk #%u padded to a 16-byte boundary. Current blksize: %u.\n", (i / BLOCKSIZE), blksize);
			blksize += pad;
		}
		
		/* Save the last 16 bytes of the previous encrypted chunk to use them as the IV for the next one */
		if (i > 0)
		{
			memset(iv, 0, 16);
			memcpy(iv, &(encryptedcontentbuf[BLOCKSIZE - 16]), 16);
		}
		
		aes_encrypt(iv, buffer, encryptedcontentbuf, blksize);
		
		/* Pad data to a 64-byte boundary (required for the WAD alignment). Again, probably only needed for the last chunk */
		if ((blksize % 64) != 0)
		{
			pad = 64 - blksize % 64;
			memset(&(encryptedcontentbuf[blksize]), 0x00, pad);
			logfile("Encrypted content chunk #%u padded to a 64-byte boundary. Current blksize: %u.\n", (i / BLOCKSIZE), blksize);
			blksize += pad;
		}
		
		fwrite(encryptedcontentbuf, 1, blksize, f);
		
		size2 += blksize;
	}
	
	logfile("Content added successfully. Original content size: %u bytes. size2: %u bytes.\n", size, size2);
	
	free(buffer);
	free(encryptedcontentbuf);
	ISFS_Close(fd);
	
	if (ret < 0)
	{
		//printf("Failed to read data into content buffer.");
		logfile("Failed to read data into content buffer.");
		fclose(f);
		Unmount_Devices();
		Reboot();
	}
	
	printf("done.\n");
	
	header->data_len += size2;
	return size2;
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

void GetSharedContent(FILE *f, u16 index, u8* hash, map_entry_t *cm, u32 elements)
{
	u32 i;
	bool found = false;
	u8 *shared_buf;
	u32 shared_size;
	char path[32] ATTRIBUTE_ALIGN(32);
	
	printf("Adding shared content... ");
	for (i = 0; i < elements; i++)
	{
		if(memcmp(cm[i].sha1, hash, 20) == 0)
		{
			found = true;
			sprintf(path, "/shared1/%.8s.app", cm[i].filename);
			logfile("Found shared content! Path is '%s'.\nReading... ", path);
			shared_size = read_isfs(path, &shared_buf);
			if (shared_size == 0)
			{
				printf("\nReading content failed, size = 0.\n");
				logfile("\nReading content failed, size = 0.\n");
				Unmount_Devices();
				Reboot();
			}
			logfile("done.\n");
			
			if ((shared_size % 16) != 0)
			{
				/* Required for the encryption process */
				logfile("Padding decrypted data to a 16-byte boundary... ");
				shared_size = pad_data(shared_buf, shared_size, true);
				logfile("done. New size: %u bytes.\n", shared_size);
			}
			
			u8 *encryptedcontentbuf = allocate_memory(shared_size);
			if(encryptedcontentbuf == NULL) 
			{ 
				//printf("\nError allocating memory for encryptedcontentbuf."); 
				logfile("\nError allocating memory for encryptedcontentbuf.");
				free(shared_buf);
				Unmount_Devices();
				Reboot(); 
			}
			
			static u8 iv[16];
			memset(iv, 0, 16);
			memcpy(iv, &index, 2);
			aes_encrypt(iv, shared_buf, encryptedcontentbuf, shared_size);
			
			free(shared_buf);
			
			if ((shared_size % 64) != 0)
			{
				/* Required for the WAD alignment */
				logfile("Padding encrypted data to a 64-byte boundary... ");
				shared_size = pad_data(encryptedcontentbuf, shared_size, false);
				logfile("done. New size: %u bytes.\n", shared_size);
			}
			
			logfile("Writing... ");
			u32 writeindex = 0;
			u32 restsize = shared_size;
			while (restsize > 0)
			{
				if (restsize >= SD_BLOCKSIZE)
				{
					fwrite(&(encryptedcontentbuf[writeindex]), 1, SD_BLOCKSIZE, f);
					restsize = restsize - SD_BLOCKSIZE;
					writeindex = writeindex + SD_BLOCKSIZE;
				} else {
					fwrite(&(encryptedcontentbuf[writeindex]), 1, restsize, f);
					restsize = 0;
				}
			}
			logfile("done. Content added successfully.\n");
			
			header->data_len += shared_size;
			free(encryptedcontentbuf);
			break;
		}
	}
	
	if(found == false)
	{
		printf("\nCould not find the shared content, no hash did match!");
		logfile("Could not find the shared content, no hash did match!\n");
		logfile("\nSHA1 of not found content: ");
		hex_key_dump(hash, 20);
		Unmount_Devices();
		Reboot();
	}
	
	printf("done.\n");
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
	logfile("GETDIR_%s: path = '%s'.\n", DEVICE(1), path);
	
	u32 i = 0;
	DIR *dip;
    struct dirent *dit;
	char pbuf[ISFS_MAXPATH + 1];
	
	if ((dip = opendir(path)) == NULL)
    {
        //printf("Error opendir.\n");
		logfile("Error opendir.\n");
        return 0;
    }
	
    while ((dit = readdir(dip)) != NULL) i++;
	
	closedir(dip);
	*ent = allocate_memory(sizeof(dirent_t) * i);
	i = 0;
	
	dip = opendir(path);
	if (dip == NULL)
    {
		//printf("Error opendir.\n");
		logfile("Error opendir.\n");
		return 0;
    }
	
	logfile("%s DIR list of '%s':\n\n", DEVICE(1), path);
	
    while ((dit = readdir(dip)) != NULL)
    {
		if(strncmp(dit->d_name, ".", 1) != 0 && strncmp(dit->d_name, "..", 2) != 0)
		{
			strcpy((*ent)[i].name, dit->d_name);
			sprintf(pbuf, "%s/%s", path, dit->d_name);
			logfile("%s\n", pbuf);
			(*ent)[i].type = ((isdir_device(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
			
			i++;
			//printf("\n%s", dit->d_name);
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
		} else
		{
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
		if(ret == -1)
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
				if(ret == -1)
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
		if(ret == -1)
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
		if (name[i] == '?' || name[i] == '[' || name[i] == ']' || name[i] == '/' || name[i] == '\\' || \
			name[i] == '=' || name[i] == '+' || name[i] == '<' || name[i] == '>' || name[i] == ':' || \
			name[i] == ';' || name[i] == '\"' || name[i] == ',' || name[i] == '*' || name[i] == '|' || \
			name[i] == '^')
		{
			name[i] = '_';
		}
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
		//sprintf(device_path, "%s:/BlueDump/Savedata/DISC %s", DEVICE(0), temp);
		sprintf(device_path, "%s:/BlueDump/Savedata/DISC %s - %s", DEVICE(0), temp, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: disc-based game.\n");
	} else
	if(TITLE_UPPER(titleID) == 0x00010001)
	{
		//sprintf(device_path, "%s:/BlueDump/Savedata/CHAN %s", DEVICE(0), temp);
		sprintf(device_path, "%s:/BlueDump/Savedata/CHAN %s - %s", DEVICE(0), temp, RemoveIllegalCharacters(get_name(titleID, false)));
		logfile("Savedata type: downloaded channel title.\n");
	} else
	if(TITLE_UPPER(titleID) == 0x00010004)
	{
		//sprintf(device_path, "%s:/BlueDump/Savedata/CHSV %s", DEVICE(0), temp);
		sprintf(device_path, "%s:/BlueDump/Savedata/CHSV %s - %s", DEVICE(0), temp, RemoveIllegalCharacters(get_name(titleID, false)));
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
	
	sprintf(device_path, "%s:/BlueDump/Savedata", DEVICE(0));
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
	snprintf(ascii_id, 5, "%s", (char *)(&name));
	return ascii_id;
}

void browser(char cpath[ISFS_MAXPATH + 1], dirent_t* ent, int cline, int lcnt)
{
	int i;
	resetscreen();
	printheadline();
	
	logfile("\n\nBROWSER: Using Wii NAND. Inserted device: %s.\nPath: %s\n", (isSD ? "SD Card" : "USB Storage"), cpath);
	
	printf("[1/Y] Dump Options  [A] Confirm/Enter Directory  [2/X] Change view mode\n");
	printf("[B] Cancel/Return to Parent Directory  [Home/Start] Exit\n\n");
	
	printf("Path: %s\n\n", cpath);
	
	if (lcnt == 0)
	{
		printf("No files/directories found!");
		printf("\nPress B to go back to the previous dir.");
	} else {
		for(i = (cline / 16)*16; i < lcnt && i < (cline / 16)*16+16; i++)
		{
			if (strncmp(cpath, "/title", 6) == 0 && strlen(cpath) == 6)
			{
				if (strncmp(ent[i].name, "00010000", 8) == 0)
				{
					printf("%s 00010000 - Disc Savedata\n", (i == cline ? "->" : "  "));
				} else
				if (strncmp(ent[i].name, "00010001", 8) == 0)
				{
					printf("%s 00010001 - Installed Channel Titles\n", (i == cline ? "->" : "  "));
				} else
				if (strncmp(ent[i].name, "00000001", 8) == 0)
				{
					printf("%s 00000001 - System Titles\n", (i == cline ? "->" : "  "));
				} else
				if (strncmp(ent[i].name, "00010002", 8) == 0)
				{
					printf("%s 00010002 - System Channel Titles\n", (i == cline ? "->" : "  "));
				} else
				if (strncmp(ent[i].name, "00010004", 8) == 0)
				{
					printf("%s 00010004 - Games that use Channels (Channel+Save)\n", (i == cline ? "->" : "  "));
				} else
				if (strncmp(ent[i].name, "00010005", 8) == 0)
				{
					printf("%s 00010005 - Downloadable Game Content (DLC)\n", (i == cline ? "->" : "  "));
				} else
				if (strncmp(ent[i].name, "00010008", 8) == 0)
				{
					printf("%s 00010008 - Hidden Channels\n", (i == cline ? "->" : "  "));
				}
			} else
			if (strncmp(cpath, "/title/00000001", 15) == 0 && strlen(cpath) == 15)
			{
				if (strncmp(ent[i].name, "00000001", 8) == 0)
				{
					printf("%s 00000001 - BOOT2\n", (i == cline ? "->" : "  "));
				} else
				if (strncmp(ent[i].name, "00000002", 8) == 0)
				{
					printf("%s 00000002 - System Menu %s\n", (i == cline ? "->" : "  "), GetSysMenuVersion(get_version(TITLE_ID(0x00000001, 0x00000002))));
				} else
				if (strncmp(ent[i].name, "00000100", 8) == 0)
				{
					printf("%s 00000100 - BC v%u\n", (i == cline ? "->" : "  "), get_version(TITLE_ID(0x00000001, 0x00000100)));
				} else
				if (strncmp(ent[i].name, "00000101", 8) == 0)
				{
					printf("%s 00000101 - MIOS v%u\n", (i == cline ? "->" : "  "), get_version(TITLE_ID(0x00000001, 0x00000101)));
				} else
				if (strncmp(ent[i].name, "00000000", 8) == 0)
				{
					printf("%s 00000000 - Unknown System Title\n", (i == cline ? "->" : "  "));
				} else {
					printf("%s %s - IOS%u v%u\n", (i == cline ? "->" : "  "), ent[i].name, (u32)strtol(ent[i].name, NULL, 16), get_version(TITLE_ID(0x00000001, strtoll(ent[i].name, NULL, 16))));
				}		
			} else
			if (strncmp(cpath, "/title/00010008", 15) == 0 && strlen(cpath) == 15)
			{
				if (strncmp(ent[i].name, "48414b45", 8) == 0)
				{
					printf("%s %s - EULA (USA) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HAKE" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414b45)));
				} else
				if (strncmp(ent[i].name, "48414b4a", 8) == 0)
				{
					printf("%s %s - EULA (JAP) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HAKJ" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414b4a)));
				} else
				if (strncmp(ent[i].name, "48414b4b", 8) == 0)
				{
					printf("%s %s - EULA (KOR) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HAKK" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414b4b)));
				} else
				if (strncmp(ent[i].name, "48414b50", 8) == 0)
				{
					printf("%s %s - EULA (EUR) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HAKP" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414b50)));
				} else
				if (strncmp(ent[i].name, "48414c45", 8) == 0)
				{
					printf("%s %s - Region Select (USA) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HALE" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414c45)));
				} else
				if (strncmp(ent[i].name, "48414c4a", 8) == 0)
				{
					printf("%s %s - Region Select (JAP) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HALJ" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414c4a)));
				} else
				if (strncmp(ent[i].name, "48414c4b", 8) == 0)
				{
					printf("%s %s - Region Select (KOR) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HALK" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414c4b)));
				} else
				if (strncmp(ent[i].name, "48414c50", 8) == 0)
				{
					printf("%s %s - Region Select (EUR) v%u\n", (i == cline ? "->" : "  "), (ascii ? "HALP" : ent[i].name), get_version(TITLE_ID(0x00010008, 0x48414c50)));
				} else
				if (strncmp(ent[i].name, "44564458", 8) == 0)
				{
					printf("%s %s - DVDx (pre-4.2 fix)\n", (i == cline ? "->" : "  "), (ascii ? "DVDX" : ent[i].name));
				} else
				if (strncmp(ent[i].name, "44495343", 8) == 0)
				{
					printf("%s %s - DVDx (new version)\n", (i == cline ? "->" : "  "), (ascii ? "DISC" : ent[i].name));
				} else {
					printf("%s %s - Unknown Hidden Channel\n", (i == cline ? "->" : "  "), (ascii ? GetASCII(strtoll(ent[i].name, NULL, 16)) : ent[i].name));
				}
			} else
			if(ent[i].function == TYPE_SAVEDATA)
			{
				printf("%s %s - %s\n", (i == cline ? "->" : "  "), (ascii ? GetASCII(strtoll(ent[i].name, NULL, 16)) : ent[i].name), get_name(TITLE_ID(0x00010000, strtoll(ent[i].name, NULL, 16)), true));
			} else
			if(ent[i].function == TYPE_TITLE)
			{
				printf("%s %s - %s\n", (i == cline ? "->" : "  "), (ascii ? GetASCII(strtoll(ent[i].name, NULL, 16)) : ent[i].name), get_name(TITLE_ID(0x00010001, strtoll(ent[i].name, NULL, 16)), true));
			} else
			if(ent[i].function == TYPE_SYSTITLE)
			{
				printf("%s %s - %s\n", (i == cline ? "->" : "  "), (ascii ? GetASCII(strtoll(ent[i].name, NULL, 16)) : ent[i].name), get_name(TITLE_ID(0x00010002, strtoll(ent[i].name, NULL, 16)), false));
			} else
			if(ent[i].function == TYPE_GAMECHAN)
			{
				printf("%s %s - %s\n", (i == cline ? "->" : "  "), (ascii ? GetASCII(strtoll(ent[i].name, NULL, 16)) : ent[i].name), get_name(TITLE_ID(0x00010004, strtoll(ent[i].name, NULL, 16)), true));
			} else
			if(ent[i].function == TYPE_DLC)
			{
				printf("%s %s - %s\n", (i == cline ? "->" : "  "), (ascii ? GetASCII(strtoll(ent[i].name, NULL, 16)) : ent[i].name), get_name(TITLE_ID(0x00010005, strtoll(ent[i].name, NULL, 16)), true));
			} else
			if(ent[i].function == TYPE_OTHER)
			{
				printf("%s %-12s - %s\n", (i == cline ? "->" : "  "), ent[i].name, (ent[i].type == DIRENT_T_DIR ? "Directory" : "File"));
			}
		}
	}
}

void make_header()
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
	static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);

	const tik *p_tik;
	p_tik = (tik *)SIGNATURE_PAYLOAD(s_tik);
	u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
	memcpy(keyin, enc_key, sizeof(keyin));
	logfile("\nEncrypted Title Key = ");
	hex_key_dump(keyin, sizeof(keyin));

	memset(keyout, 0, sizeof(keyout));

	memset(iv, 0, sizeof(iv));

	memcpy(iv, &p_tik->titleid, sizeof(p_tik->titleid));
  
	aes_set_key(commonkey);
	aes_decrypt(iv, keyin, keyout, sizeof(keyin));
	memcpy(key, keyout, sizeof(keyout));
	logfile("\nDecrypted Title Key = ");
	hex_key_dump(keyout, sizeof(keyout));
	logfile("\n");
}

s32 Wad_Dump(u64 id, char *path, bool ftik, bool ftmd)
{
	make_header();
	
	logfile("Started WAD Packing...\nPacking Title %08x-%08x\n", TITLE_UPPER(id), TITLE_LOWER(id));

	signed_blob *p_tik = NULL;
	signed_blob *p_tmd = NULL;
	
	tmd *tmd_data  = NULL;
	u8 key[16];
	
	u32 cnt = 0;
	
	FILE *wadout;
	if (!create_folders(path))
	{
		//printf("Error creating folder(s) for '%s'.\n", path);
		logfile("Error creating folder(s) for '%s'.\n", path);
		return -1;
	}

	wadout = fopen(path, "wb");
	if (!wadout)
	{
		//printf("\nfopen error.\n");
		logfile("fopen error.\n");
		Unmount_Devices();
		Reboot();
	}
	
	/* Reserve space for the header */
	u8 *padding_table = allocate_memory(64);
	if (padding_table == NULL)
	{
		//printf("Out of memory.\n");
		logfile("Out of memory\n");
		fclose(wadout);
		free(header);
		Unmount_Devices();
		Reboot();
	}
	memset(padding_table, 0, 64);
	fwrite(padding_table, 1, 64, wadout);
	free(padding_table);
	
	/* Get Certs */
	printf("Reading Certs... ");
	logfile("Reading Certs... ");
	fflush(stdout);
	header->certs_len = GetCerts(wadout);
	check_not_0(header->certs_len, "Error getting Certs.\n");
	printf("done.\n");
	logfile("done.\n");
	
	/* Get Ticket */
	printf("Reading Ticket... ");
	logfile("Reading Ticket... ");
	if (!ftik)
	{
		GetTicket(wadout, id, &p_tik, false);
	} else {
		GetTicket(wadout, id, &p_tik, true);
	}
	check_not_0(header->tik_len, "Error getting Ticket.\n");
	printf("done.\n");
	logfile("done.\n");
	
	/* Get TMD */
	printf("Reading TMD... ");
	logfile("Reading TMD... ");
	if (!ftmd)
	{
		GetTMD(wadout, id, &p_tmd, false);
	} else {
		GetTMD(wadout, id, &p_tmd, true);
	}
	check_not_0(header->tmd_len, "Error getting TMD.\n");
	printf("done.\n");
	logfile("done.\n");
	
	/* Get Title Key */
	printf("Decrypting AES Title Key... ");
	logfile("Decrypting AES Title Key... ");
	get_title_key(p_tik, (u8 *)key);
	aes_set_key(key);
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
		
		u32 len2 = 0;
		
		u16 type = 0;
		
		type = content->type;
		switch(type)
		{
			case 0x0001: // Normal
				len2 = GetContent(wadout, id, content->cid, content->index, (u32)content->size);
				check_not_0(len2, "Error reading content.\n");
				break;
			case 0x8001: // Shared
				GetSharedContent(wadout, content->index, content->hash, cm, content_map_items);
				break;
			case 0x4001: // DLC
				len2 = GetContent(wadout, id, content->cid, content->index, (u32)content->size);
				check_not_0(len2, "Error reading content.\n");
				break;
			default:
				printf("Unknown content type: 0x%04x. Aborting mission...\n", type);
				logfile("Unknown content type: 0x%04x. Aborting mission...\n", type);
				sleep(2);
				Unmount_Devices();
				Reboot();
				break;
		}
		
		if (cnt == 0) sprintf(footer_path, "/title/%08x/%08x/content/%08x.app", TITLE_UPPER(id), TITLE_LOWER(id), content->cid);
	}
	
	free(p_tmd);
	
	/* Add unencrypted footer */
	u8 *footer_buf;
	u32 footer_size;
	printf("Adding footer... ");
	logfile("Adding footer... ");
	footer_size = read_isfs(footer_path, &footer_buf);
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

u64 copy_id_sd_save(char *path, bool disc, bool channel)
{
	u32 low = 0;
	
	u64 titleID;
	memcpy(&low, path+27, 4);
	
	logfile("copy_id_sd_save low = %08x.\n", low);
	
	if (disc && !channel)
	{
		logfile("copy_id_sd_save: disc.\n");
		titleID = TITLE_ID(0x00010000, low);
	} else
	if (!disc && channel)
	{
		logfile("copy_id_sd_save: channel.\n");
		titleID = TITLE_ID(0x00010001, low);
	} else {
		logfile("copy_id_sd_save: gamechan.\n");
		titleID = TITLE_ID(0x00010004, low);
	}
	
	logfile("Generated copy_id_sd_save ID was '%08x-%08x'.\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	
	return titleID;
}

bool for_tik = false;
bool for_tmd = false;

void select_forge()
{
	u32 pressed;
	u32 pressedGC;

	printf("\n\nDo you want to fakesign the ticket?");
	printf("\n[A] Yes (recommended)   [B] No\n");
	
	while(true)
	{
		waitforbuttonpress(&pressed, &pressedGC);
		
		if (pressed == WPAD_BUTTON_A || pressedGC == PAD_BUTTON_A)
		{
			for_tik = true;
			logfile("forge_tik set to true.\n");
			break;
		}
		
		if (pressed == WPAD_BUTTON_B || pressedGC == PAD_BUTTON_B)
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
		waitforbuttonpress(&pressed, &pressedGC);
		
		if (pressed == WPAD_BUTTON_A || pressedGC == PAD_BUTTON_A)
		{
			for_tmd = true;
			logfile("forge_tmd set to true.\n");
			break;
		}
		
		if (pressed == WPAD_BUTTON_B || pressedGC == PAD_BUTTON_B)
		{
			for_tmd = false;
			logfile("forge_tmd set to false.\n");
			break;
		}
	}
}

void dump_menu(char *cpath, char *tmp, int cline, int lcnt, dirent_t *ent)
{
	u32 pressed;
	u32 pressedGC;
	
	bool go_back = false;
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
		
		waitforbuttonpress(&pressed, &pressedGC);
		
		if (pressed == WPAD_BUTTON_LEFT || pressedGC == PAD_BUTTON_LEFT)
		{	
			if (selection > 0)
			{
				selection--;
			}
		}
		
		if (pressed == WPAD_BUTTON_RIGHT || pressedGC == PAD_BUTTON_RIGHT)
		{	
			if (selection < 2)
			{
				selection++;
			}
		}
		
		if (pressed == WPAD_BUTTON_B || pressedGC == PAD_BUTTON_B)
		{
			go_back = true;
			break;
		}
		
		if (pressed == WPAD_BUTTON_A || pressedGC == PAD_BUTTON_A) break;
	}
	
	if (!go_back)
	{
		char some[500];
		strcpy(tmp, cpath);
		if(strcmp(cpath, "/") != 0)
		{
			sprintf(some, "%s/%s", tmp, ent[cline].name);
		} else {				
			sprintf(some, "/%s", ent[cline].name);
		}
		
		u64 titleID;
		
		logfile("cline: %s.\n", some);
		switch(selection)
		{
			case 0: // Backup savedata
				if (ent[cline].function == TYPE_SAVEDATA || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
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
				if (ent[cline].function == TYPE_SAVEDATA || ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_GAMECHAN)
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
				if (ent[cline].function == TYPE_SAVEDATA || ent[cline].function == TYPE_OTHER)
				{
					printf("This is not a title! Use the savedata functions for this.\n");
				} else {
					logfile("Creating WAD...\n");
					
					select_forge();
					
					resetscreen();
					printheadline();
					printf("Creating WAD...\n");
					
					char dump_path[256];
					
					switch (ent[cline].function)
					{
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
					
					if (ent[cline].function == TYPE_TITLE || ent[cline].function == TYPE_SYSTITLE || ent[cline].function == TYPE_GAMECHAN || ent[cline].function == TYPE_DLC || ent[cline].function == TYPE_HIDDEN)
					{
						/* Workaround for HBC 1.0.7 - 1.1.0 */
						if (low != 0xAF1BF516)
						{
							if (ent[cline].function == TYPE_HIDDEN)
							{
								if (strncmp(ent[cline].name, "48414b", 6) == 0)
								{
									sprintf(dump_path, "%s:/BlueDump/WAD/EULA v%u - %s", DEVICE(0), get_version(titleID), GetASCII(low));
								} else
								if (strncmp(ent[cline].name, "48414c", 6) == 0)
								{
									sprintf(dump_path, "%s:/BlueDump/WAD/RgnSel v%u - %s", DEVICE(0), get_version(titleID), GetASCII(low));
								} else {
									sprintf(dump_path, "%s:/BlueDump/WAD/00010008-%s v%u", DEVICE(0), GetASCII(low), get_version(titleID));
								}
							} else {
								sprintf(dump_path, "%s:/BlueDump/WAD/%s v%u - %s", DEVICE(0), RemoveIllegalCharacters(get_name(titleID, false)), get_version(titleID), GetASCII(low));
							}
						} else {
							sprintf(dump_path, "%s:/BlueDump/WAD/Homebrew Channel - AF1BF516", DEVICE(0));
						}
					} else
					if (ent[cline].function == TYPE_IOS)
					{
						if (low == 0x00000002)
						{
							sprintf(dump_path, "%s:/BlueDump/WAD/System Menu %s", DEVICE(0), GetSysMenuVersion(get_version(titleID)));
						} else
						if (low == 0x00000100)
						{
							sprintf(dump_path, "%s:/BlueDump/WAD/BC v%u", DEVICE(0), get_version(titleID));
						} else
						if (low == 0x00000101)
						{
							sprintf(dump_path, "%s:/BlueDump/WAD/MIOS v%u", DEVICE(0), get_version(titleID));
						} else {
							sprintf(dump_path, "%s:/BlueDump/WAD/IOS%u v%u", DEVICE(0), (u32)strtol(ent[cline].name,NULL,16), get_version(titleID));
						}
					}
					
					if (for_tik && for_tmd)
					{
						strncat(dump_path, " (ftmd+ftik).wad", 16);
						logfile("Path for dump = %s.\n", dump_path);
						Wad_Dump(titleID, dump_path, true, true);
					} else
					if (!for_tik && for_tmd)
					{
						strncat(dump_path, " (ftmd).wad", 11);
						logfile("Path for dump = %s.\n", dump_path);
						Wad_Dump(titleID, dump_path, false, true);
					} else
					if (for_tik && !for_tmd)
					{
						strncat(dump_path, " (ftik).wad", 11);
						logfile("Path for dump = %s.\n", dump_path);
						Wad_Dump(titleID, dump_path, true, false);
					} else {
						strncat(dump_path, ".wad", 4);
						logfile("Path for dump = %s.\n", dump_path);
						Wad_Dump(titleID, dump_path, false, false);
					}
					
					logfile("WAD dump complete!\n");
					printf("WAD dump complete! Output file:\n\n\t%s", dump_path);
				}
				break;
			default:
				break;
		}
		
		sleep(3);
	}

	browser(cpath, ent, cline, lcnt);
}

void bluedump_loop()
{
	int i = 0;
	u32 pressed;
	u32 pressedGC;
	
	reset_log();
	logfile("BlueDump MOD v0.5 - Logfile.\n");
	logfile("SDmnt(%d), USBmnt(%d), isSD(%d).\n\n", SDmnt, USBmnt, isSD);
	
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
	
	char tmp[ISFS_MAXPATH + 1];
	char cpath[ISFS_MAXPATH + 1];	
	dirent_t* ent = NULL;
	u32 lcnt = 0;
	u32 cline = 0;
	sprintf(cpath, ROOT_DIR);
	getdir_info(cpath, &ent, &lcnt);
	cline = 0;
	browser(cpath, ent, cline, lcnt);
	
	while(true)
	{
		waitforbuttonpress(&pressed, &pressedGC);
		
		/* Navigate up */
		if (pressed == WPAD_BUTTON_UP || pressedGC == PAD_BUTTON_UP)
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
		if (pressed == WPAD_BUTTON_DOWN || pressedGC == PAD_BUTTON_DOWN)
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
		if (pressed == WPAD_BUTTON_LEFT || pressedGC == PAD_BUTTON_LEFT)
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
		if (pressed == WPAD_BUTTON_RIGHT || pressedGC == PAD_BUTTON_RIGHT)
		{
			cline += 4;
			
			if (cline > (lcnt - 1)) cline = lcnt - 1;
			
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Enter parent dir */
		if (pressed == WPAD_BUTTON_B || pressedGC == PAD_BUTTON_B)
		{
			int len = strlen(cpath);
			for(i = len; cpath[i] != '/'; i--);
			
			if(i == 0)
			{
				strcpy(cpath, ROOT_DIR);
			} else {
				cpath[i] = 0;
			}
			
			getdir_info(cpath, &ent, &lcnt);
			
			cline = 0;
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Enter dir */
		if (pressed == WPAD_BUTTON_A || pressedGC == PAD_BUTTON_A)
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
				
				cline = 0;
				printf("cline: %s.\n", cpath);
			}
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Dump options */
		if (pressed == WPAD_BUTTON_1 || pressedGC == PAD_BUTTON_Y)
		{
			if (lcnt != 0 && strlen(cpath) == 15)
			{
				dump_menu(cpath, tmp, cline, lcnt, ent);
			}
		}
		
		/* Change view mode */
		if (pressed == WPAD_BUTTON_2 || pressedGC == PAD_BUTTON_X)
		{
			ascii ^= 1;
			browser(cpath, ent, cline, lcnt);
		}
		
		/* Chicken out */
		if (pressed == WPAD_BUTTON_HOME || pressedGC == PAD_BUTTON_START)
		{
			free(cm);
			free(ent);
			break; 
		}
	}
	
	printf("\nExiting...");
	
	/* End of app loop */
}
