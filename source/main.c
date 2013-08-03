/*******************************************************************************
 * main.c
 *
 * Copyright (c) 2009 Nicksasa
 *
 * Distributed under the terms of the GNU General Public License (v2)
 * See http://www.gnu.org/licenses/gpl-2.0.txt for more info.
 *
 ******************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <ogcsys.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <gccore.h>
#include <network.h>
#include <sys/fcntl.h>
#include <ogc/isfs.h>
#include <fat.h>
#include <fcntl.h>
#include <sys/unistd.h>
#include <dirent.h>
#include <sdcard/wiisd_io.h>
#include <wiiuse/wpad.h>

#include "rijndael.h"

#define BLOCKSIZE 2048
#define SD_BLOCKSIZE 1024 * 32

#define DIRENT_T_FILE 0
#define DIRENT_T_DIR 1

#define TYPE_SAVEDATA 	0
#define TYPE_TITLE 		1
#define TYPE_IOS		2
#define TYPE_UNKNOWN 	9

#define TITLE_UPPER(x)		((u32)((x) >> 32))
#define TITLE_LOWER(x)		((u32)(x))
#define TITLE_ID(x,y)		(((u64)(x) << 32) | (y))


#define round_up(x,n)   (-(-(x) & -(n)))
#define round64(x)      round_up(x,0x40)
#define	round16(x)		round_up(x,0x10)

#define SAVE_HOST 			"myfail.net"
#define SAVE_PORT			80
#define SAVE_DB				"/save_db.txt"
#define TEMP_DB				"sd:/BlueDump/temp.txt"
#define TEMP_SAVE_FOLDER	"sd:/BlueDump"

//#define DEBUG

u32 *xfb = NULL;
GXRModeObj *rmode = NULL;

u8 commonkey[16] = { 0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7 };
static vu32 *_wiilight_reg = (u32*)0xCD0000C0;
char ascii(char s) 
{
    if(s < 0x20) return '.';
    if(s > 0x7E) return '.';
    return s;
}

void reset_log()
{
	remove("sd:/BlueDump.log");
}	

void logfile(const char *format, ...)
{
	#ifdef DEBUF
	u32 val = (*_wiilight_reg&~0x20);
	u32 enable = 1;
    if (enable) val |= 0x20;
    *_wiilight_reg=val;
	char buffer[256];
	va_list args;
	va_start (args, format);
	vsprintf (buffer,format, args);
	FILE *f;
	f = fopen("sd:/BlueDump.log", "a");
	if (!f)
	{
		printf("Error writing log\n");
		return;
	}
	fputs(buffer, f);
	fclose(f);
	va_end (args);
	val = (*_wiilight_reg&~0x20);
	enable = 0;
    if (enable) val |= 0x20;
    *_wiilight_reg=val;
	#endif
}

void hexdump_log(void *d, int len)
{
    u8 *data;
    int i, f, off;
    data = (u8*)d;
    for (off=0; off<len; off += 16) 
	{
        logfile("%08x:  ",16*(off/16));
		for(f=0; f < 16; f += 4)
		{
			for(i=0; i<4; i++)
			{
				if((i+off)>=len)
				{
					logfile(" ");
				} else
				{
					logfile("%02x",data[off+f+i]);
				}  
                
				//logfile(" ");
			}
			logfile(" ");
		}	
		logfile("\n");
		//logfile(" ");
    }		
    logfile("\n");
}

bool MakeDir(const char *Path)
{
	logfile("makedir path = %s\n", Path);
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
typedef struct 
{
	char link[128];
} link_t;	

typedef struct 
{
	char name[128];
	char id[6];
	link_t *links;
	u32 completion;
} save_db_t;
typedef struct _dir
{
	char name[ISFS_MAXPATH + 1];
} dir_t;

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

wadHeader   *header;

typedef struct 
{
	u8 cid[8];
	u8 sha1[20];
} map_content;
s32 initialise_network() {
    s32 result;
    while ((result = net_init()) == -EAGAIN);
    return result;
}
void resetscreen()
{
	printf("\x1b[2J");
}
void Con_ClearLine()
{
	s32 cols, rows;
	u32 cnt;

	printf("\r");
	fflush(stdout);

	/* Get console metrics */
	CON_GetMetrics(&cols, &rows);

	/* Erase line */
	for (cnt = 1; cnt < cols; cnt++) {
		printf(" ");
		fflush(stdout);
	}

	printf("\r");
	fflush(stdout);
}

void *allocate_memory(u32 size)
{
	return memalign(32, (size+63)&(~63) );
}


void videoInit()
{
	VIDEO_Init();
	rmode = VIDEO_GetPreferredMode(0);
	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();
 	

	
	// Set console text color
	printf("\x1b[%u;%um", 37, false);
	printf("\x1b[%u;%um", 40, false);
	
    int x = 24, y = 32, w, h;
    w = rmode->fbWidth - (32);
    h = rmode->xfbHeight - (48);
	CON_InitEx(rmode, x, y, w, h);

	VIDEO_ClearFrameBuffer(rmode, xfb, COLOR_BLACK);
}

void read_links(char *line, link_t **out, u32 *count)
{
	(*out) = allocate_memory(sizeof(link_t) * 30);
	u32 i = 0;

	u32 e = 0;
	u32 f = 0;
	
	if(strncmp(line, "LINK = ", 7) == 0)
	{
		i+= 7;
			
		while( (strcmp(line + i, " STOP") != 0) && (i <=strlen(line)) )
		{
			//strcpy(out[e], line[i]);
			if(strncmp(line+i, " ", 1) == 0)
			{
				f++;
				i++;
				e = 0;
			}	
			(*out)[f].link[e] = line[i];
			e++;
			i++;
		}
		logfile("%s\n", (*out)[f - 1].link);
	}
	*count = f;	
}
char *read_name(char *line)
{


	char *buf;
	buf = allocate_memory(128);
	if(strncmp(line, "NAME = ", 7) == 0)
	{
			strncpy(buf, line + 7, strlen(line) - 7);
			logfile("NAME = %u\n", buf);
	
	} else
	{
		strcpy(buf, " ");
	}	
	return buf;

}	

char *read_id(char *line)
{


	char *buf;
	buf = allocate_memory(6);
	if(strncmp(line, "ID = ", 5) == 0)
	{
			strcpy(buf, line + 5);
			logfile("ID = %u\n", buf);
	
	} else
	{
		strcpy(buf, " ");
	}	
	return buf;

}	
u32 read_completion(char *line)
{


	u32 temp = 0;
	if(strncmp(line, "COMPLETION = ", 13) == 0)
	{
			//strcpy(buf, line + 13);
			sscanf(line + 13, "%d", &temp);
			logfile("Completion = %u\n", temp);
			return temp;
	
	} else
	{
		//strcpy(buf, " ");
		return 0;
	}	

}	

void parse_save_db(char *path, char *name, char *id, u32 *completion, link_t **links, u32 *link_count)
{
	char buffer[4096];
	FILE *fp = fopen(path, "r");
	while (!feof(fp)) 
	{
		fgets(buffer, 4000, fp);
		if(strncmp(buffer, "NAME = ", 7) == 0)
		{
			name = read_name(buffer);
	
		}
		if(strncmp(buffer, "ID = ", 5) == 0)
		{
			id = read_id(buffer);
	
		}
		if(strncmp(buffer, "COMPLETION = ", 13) == 0)
		{
			*completion = read_completion(buffer);
	
		}
		if(strncmp(buffer, "LINK = ", 7) == 0)
		{
			read_links(buffer, links, link_count);
	
		}
	
    }
	fclose(fp);
}	
void parse_db(char *path, save_db_t *saves, u32 *count)
{

	/*char name[128];
	char id[6];
	link_t *links;
	u32 completion;
	save_db_t; */

	if (!create_folders(TEMP_DB))
	{
		printf("Error creating folder(s) for '%s'\n", TEMP_DB);
		return;
	}

	FILE *db = fopen(TEMP_DB, "wb");	
	u32 db_size = 0;
	u32 save_db_size = 0;
	
	network_init();
	ReadNetwork(SAVE_DB, db, &db_size, SAVE_HOST, SAVE_PORT);
	fclose(db);
	char buffer[4096];
	char host_path[256];
	char sd_path[256];
	FILE *fp = fopen(TEMP_DB, "r");
	while (!feof(fp)) 
	{
		fgets(buffer, 4000, fp);

		sprintf(host_path, "/savedata/%s/db.txt", buffer);
		logfile("host_path = %s\n", host_path);
		sprintf(sd_path, "sd:/BlueDump/Savedata/%s", buffer);
		logfile("sd_path = %s\n", sd_path);
		sprintf(sd_path, "sd:/BlueDump/Savedata/%s/db.txt", buffer);
		logfile("sd_path = %s\n", sd_path);

		if (!create_folders(sd_path))
		{
			printf("Error creating folder(s) for '%s'\n", sd_path);
			return;
		}
		FILE *temp = fopen(sd_path, "wb");
		ReadNetwork(host_path, temp, &save_db_size, SAVE_HOST, SAVE_PORT);
		fclose(temp);
	
    }
	fclose(fp);
}	
void check_not_0(size_t ret, char *error)
{
	if(ret == 0)
	{
		printf(error);
		logfile(error);
		sleep(5);
		exit(0);
	}	
}	

void decrypt_buffer(u16 index, u8 *source, u8 *dest, u32 len) {
  static u8 iv[16];
  if (!source) 
  {
	printf("decrypt_buffer: invalid source paramater\n");
  }
  if (!dest) 
  {
	printf("decrypt_buffer: invalid dest paramater\n");
  }

  memset(iv, 0, 16);
  memcpy(iv, &index, 2);
  aes_decrypt(iv, source, dest, len);
  
}

void encrypt_buffer(u16 index, u8 *source, u8 *dest, u32 len) {
  static u8 iv[16];
  if (!source) 
  {
	printf("decrypt_buffer: invalid source paramater\n");
	
  }
  if (!dest) 
  {
	printf("decrypt_buffer: invalid dest paramater\n");
	
  }

  memset(iv, 0, 16);
  memcpy(iv, &index, 2);
  aes_encrypt(iv, source, dest, len);
}
u32 get_app_size(signed_blob *tmd_b)
{

	u32 len;
	u32 rounded_len;
	u32 len_total=0;
	u16 num_contents;
	u32 i;
	tmd *tmd_buf;
	tmd_buf = (tmd *)SIGNATURE_PAYLOAD(tmd_b);

	num_contents = tmd_buf->num_contents;

	for (i = 0; i < num_contents; i++) {
		tmd_content *content = &tmd_buf->contents[i];
		len = content->size;
		rounded_len = round64(len);
		len_total+=rounded_len;
		 

	}
	return len_total;
	
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
	if(res < 0)
		return 0;
		
	return 1;
}
u16 get_version(char *path, char *folder)
{
	char buffer[256];
	s32 cfd;
	s32 ret;
	u16 version;
	u8 *tmdbuf = (u8*)memalign(32, 1024);
	
	sprintf(buffer, "%s/%s/content/title.tmd", path, folder);
	logfile("%s\n", buffer);
	cfd = ISFS_Open(buffer, ISFS_OPEN_READ);
    if (cfd < 0)
	{
		printf("ISFS_OPEN for %s failed %d\n", path, cfd);
		logfile("ISFS_OPEN for %s failed %d\n", path, cfd);
		sleep(5);
		exit(0);
	}
			
    ret = ISFS_Read(cfd, tmdbuf, 1024);
	if (ret < 0)
	{
		printf("ISFS_Read for %s failed %d\n", path, ret);
		logfile("ISFS_Read for %s failed %d\n", path, ret);
		ISFS_Close(cfd);
		sleep(5);
		exit(0);
		
	}

    ISFS_Close(cfd);
	memcpy(&version, tmdbuf+0x1DC, 2);
	logfile("version = %u\n",version);
	free(tmdbuf);
	return version;
}	
s32 getdir(char *path, dirent_t **ent, u32 *cnt)
{
	s32 res;
	u32 num = 0;
	char pbuf[ISFS_MAXPATH + 1];

	int i, j, k;
	
	res = ISFS_ReadDir(path, NULL, &num);
	if(res != ISFS_OK)
	{
		printf("Error: could not get dir entry count! (result: %d)\n", res);
		logfile("Error: could not get dir entry count! (result: %d)\n", res);
		return -1;
	}

	char *nbuf = (char *)allocate_memory((ISFS_MAXPATH + 1) * num);
	char ebuf[ISFS_MAXPATH + 1];

	if(nbuf == NULL)
	{
		printf("Error: could not allocate buffer for name list!\n");
		logfile("Error: could not allocate buffer for name list!\n");
		return -1;
	}

	res = ISFS_ReadDir(path, nbuf, &num);
	if(res != ISFS_OK)
	{
		printf("Error: could not get name list! (result: %d)\n", res);
		logfile("Error: could not get name list! (result: %d)\n", res);
		return -1;
	}
	
	*cnt = num;
	
	*ent = allocate_memory(sizeof(dirent_t) * num);
	logfile("ISFS DIR List of %s: \n\n", path);
	for(i = 0, k = 0; i < num; i++)
	{	    
		for(j = 0; nbuf[k] != 0; j++, k++)
			ebuf[j] = nbuf[k];
		ebuf[j] = 0;
		k++;

		strcpy((*ent)[i].name, ebuf);
		sprintf(pbuf, "%s/%s", path, ebuf);
		logfile("%s\n", pbuf);
		(*ent)[i].type = ((isdir(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
		(*ent)[i].function = TYPE_UNKNOWN;
		if(strstr(path, "00010000") != 0)
		{
			(*ent)[i].function = TYPE_SAVEDATA;
		}
		if(strstr(path, "00010001") != 0)
		{
			(*ent)[i].function = TYPE_TITLE;
		}	
		if(strstr(path, "00000001") != 0)
		{
			(*ent)[i].function = TYPE_IOS;
			(*ent)[i].version = get_version(path, ebuf);
		}
	
	}
	
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	free(nbuf);
	return 0;
}
char *read_name_from_banner_app(u64 titleid)
{
	s32 cfd;
    s32 ret;
	u32 num;
	dirent_t *list;
    char contentpath[ISFS_MAXPATH];
    char path[ISFS_MAXPATH];
	int i;
    int length;
    u32 cnt = 0;
	char *out;
	u8 *buffer = allocate_memory(800);
	   
	sprintf(contentpath, "/title/%08x/%08x/content", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
	
    ret = getdir(contentpath, &list, &num);
    if (ret < 0)
	{
		printf("Reading folder of the title failed\n");
		logfile("Reading folder of the title failed\n");
		free(buffer);
		return NULL;
	}
	
	u8 imet[4] = {0x49, 0x4D, 0x45, 0x54};
	for(cnt=0; cnt < num; cnt++)
    {        
        if (strstr(list[cnt].name, ".app") != NULL || strstr(list[cnt].name, ".APP") != NULL) 
        {
			memset(buffer, 0x00, 800);
            sprintf(path, "/title/%08x/%08x/content/%s", TITLE_UPPER(titleid), TITLE_LOWER(titleid), list[cnt].name);
  
            cfd = ISFS_Open(path, ISFS_OPEN_READ);
            if (cfd < 0)
			{
	    	    printf("ISFS_OPEN for %s failed %d\n", path, cfd);
				logfile("ISFS_OPEN for %s failed %d\n", path, cfd);
				continue;
			}
			
            ret = ISFS_Read(cfd, buffer, 800);
	        if (ret < 0)
	        {
	    	    printf("ISFS_Read for %s failed %d\n", path, ret);
				logfile("ISFS_Read for %s failed %d\n", path, ret);
		        ISFS_Close(cfd);
				continue;
	        }

            ISFS_Close(cfd);	
              
			if(memcmp((buffer+0x80), imet, 4) == 0)
			{
				length = 0;
				i = 0;
				while(buffer[0xF1 + i*2] != 0x00)
				{
					length++;
					i++;
				}
				
				out = allocate_memory(length+10);
				if(out == NULL)
				{
					printf("Allocating memory for buffer failed\n");
					logfile("Allocating memory for buffer failed\n");
					free(buffer);
					return NULL;
				}
				memset(out, 0x00, length+10);
				
				i = 0;
				while(buffer[0xF1 + i*2] != 0x00)
				{
					out[i] = (char) buffer[0xF1 + i*2];
					i++;
				}				
				
				free(buffer);
				free(list);
				
				return out;
			}
			    
        }
    }
	
	free(buffer);
	free(list);
	
	return NULL;
}

char *read_name_from_banner_bin(u64 titleid)
{
	s32 cfd;
    s32 ret;
    char path[ISFS_MAXPATH];
	int i;
    int length;
	char *out;
	u8 *buffer = allocate_memory(160);
   
	// Try to read from banner.bin first
	sprintf(path, "/title/%08x/%08x/data/banner.bin", TITLE_UPPER(titleid), TITLE_LOWER(titleid));
  
	cfd = ISFS_Open(path, ISFS_OPEN_READ);
	if (cfd < 0)
	{
		//printf("ISFS_OPEN for %s failed %d\n", path, cfd);
		return NULL;
	} else
	{
	    ret = ISFS_Read(cfd, buffer, 160);
	    if (ret < 0)
	    {
			printf("ISFS_Read for %s failed %d\n", path, ret);
			logfile("ISFS_Read for %s failed %d\n", path, ret);
		    ISFS_Close(cfd);
			free(buffer);
			return NULL;
		}

		ISFS_Close(cfd);	

		length = 0;
		i = 0;
		while(buffer[0x21 + i*2] != 0x00)
		{
			length++;
			i++;
		}
		out = allocate_memory(length+10);
		if(out == NULL)
		{
			printf("Allocating memory for buffer failed\n");
			logfile("Allocating memory for buffer failed\n");
			free(buffer);
			return NULL;
		}
		memset(out, 0x00, length+10);
		
		i = 0;
		while (buffer[0x21 + i*2] != 0x00)
		{
			out[i] = (char) buffer[0x21 + i*2];
			i++;
		}
		
		free(buffer);

		return out;		
	}
 	
	free(buffer);
	
	return NULL;
}
bool check_text(char *s) 
{
    int i = 0;
    for(i=0; i < strlen(s); i++)
    {
        if (s[i] < 32 || s[i] > 165)
		{
			return false;
		}
	}  

	return true;
}

char *get_name(u64 titleid)
{
	char *temp;
	u32 low;
	low = TITLE_LOWER(titleid);

	temp = read_name_from_banner_bin(titleid);
	if (temp == NULL || !check_text(temp))
	{
		temp = read_name_from_banner_app(titleid);
	}
	

	if (temp == NULL)
	{
		temp = allocate_memory(2);
		sprintf(temp, " ");
	}
	
	return temp;
}
char *get_name_sd(u64 titleid)
{
	char *temp;
	u32 low;
	low = TITLE_LOWER(titleid);

	temp = read_name_from_banner_bin(titleid);
	if (temp == NULL || !check_text(temp))
	{
		temp = read_name_from_banner_app(titleid);
	}
	

	if (temp == NULL)
	{
		temp = allocate_memory(2);
		sprintf(temp, " ");
	}
	
	return temp;
}
u32 pad_data_32(u8 *in, u32 len, u8 **out)
{
	u32 new_size = round64(len);

	
	u8 *buffer = allocate_memory(new_size);
	memset(buffer, 0, new_size);

	
	memcpy(buffer, in, len);


	u32 diffrence = new_size - len;
	
	u32 i = 0;
	
	for(i=0; i < diffrence; i++)
	{
		buffer[len + i] = 0x00;
	}

	free(in);
	*out = buffer;

	return new_size;
}


u32 read_isfs(char *path, u8 **out)
{

	fstats *status;
	
	s32 ret;
	u32 size;
	s32 fd;
	fd = ISFS_Open(path, ISFS_OPEN_READ);
	//printf("ISFS_Open returned %d\n", fd);
	logfile("ISFS_Open(%s) returned %d\n", path, fd);
	status = allocate_memory(sizeof(fstats) );
	if(status == NULL) 
	{
		printf("Error allocating memory for status\n"); 
		logfile("Error allocating memory for status\n"); 
		sleep(2); 
		exit(0); 
	}
	ret = ISFS_GetFileStats(fd, status);
	if (ret < 0)
	{
		printf("\nISFS_GetFileStats(fd) returned %d\n", ret);
		logfile("ISFS_GetFileStats(fd) returned %d\n", ret);
		free(status);
		sleep(2);
		return 0;
	}
	u32 fullsize = status->file_length;
	logfile("Size = %u bytes\n", fullsize);
	u8 *out2 = allocate_memory(fullsize);
	if(out2 == NULL) 
	{ 
		printf("Error allocating memory for out2\n");
		logfile("Error allocating memory for out2\n");
		free(status);
		sleep(2);
		return 0;
	}
	logfile("ISFS Blocksize = %d\n", BLOCKSIZE);
	u32 restsize = status->file_length;
	u32 writeindex = 0;
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			size = BLOCKSIZE;
		} else
		{
			size = restsize;
		}
		ret = ISFS_Read(fd, &(out2[writeindex]), size);
		if (ret < 0)
		{
			printf("\nISFS_Read(%d, %d) returned %d\n", fd, size, ret);
			logfile("\nISFS_Read(%d, %d) returned %d\n", fd, size, ret);
			free(status);
			return 0;
		}
		writeindex = writeindex + size;
		restsize -= size;
	}
	free(status);
	ISFS_Close(fd);
	*out = out2;
	return fullsize;
}

u32 GetTMD(FILE *f, u64 id, signed_blob **tmd)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;

	u32 size;
	u32 size2;
	
	sprintf(path, "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(id), TITLE_LOWER(id));

	logfile("TMD Path is %s\n", path);
	size = read_isfs(path, &buffer);
	size2 = pad_data_32(buffer, size, &buffer);
	logfile("Padded TMD size = %u\n", size2);
	fwrite(buffer, 1, size2, f);
	*tmd = (signed_blob *)buffer;
	return size;
}	

u32 GetTicket(FILE *f, u64 id, signed_blob **tik)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;

	u32 size;
	u32 size2;
	
	sprintf(path, "/ticket/%08x/%08x.tik", TITLE_UPPER(id), TITLE_LOWER(id));

	logfile("Ticket Path is %s\n", path);
	size = read_isfs(path, &buffer);
	size2 = pad_data_32(buffer, size, &buffer);
	logfile("Padded Ticket size = %u\n", size2);
	fwrite(buffer, 1, size2, f);
	*tik = (signed_blob *)buffer;

	return size;
}	

u32 GetCert(FILE *f)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;

	u32 size;
	u32 size2;
	
	sprintf(path, "/sys/cert.sys");
	logfile("Cert Path is %s\n", path);
	size = read_isfs(path, &buffer);

	size2 = pad_data_32(buffer, size, &buffer);
	logfile("Padded Cert size = %u\n", size2);
	
	fwrite(buffer, 1, size2, f);
	free(buffer);
	return size;
}	




u32 GetContent(FILE *f, u64 id, u16 content, u16 index, bool shared)
{
	char path[ISFS_MAXPATH];
	u8 *buffer;
	u8 *encryptedcontentbuf;

	u32 size;
	u32 size2;
	u32 retsize;
	
	if (shared)
	{
		sprintf(path, "/shared1/%08x.app", content);
		logfile("Shared content path is %s\n", path);
		printf("Adding shared content...\n");
	} else
	{
		sprintf(path, "/title/%08x/%08x/content/%08x.app", TITLE_UPPER(id), TITLE_LOWER(id), content);
		logfile("Regular content path is %s\n", path);
		printf("Adding regular content...\n");
	}


	logfile("Reading...\n");
	size = read_isfs(path, &buffer);
	if (size == 0)
	{
		printf("Reading content failed, size = 0\n");
		logfile("Reading content failed, size = 0\n");
		sleep(5);
		exit(0);
	}

	size2 = pad_data_32(buffer, size, &buffer);
	encryptedcontentbuf = allocate_memory(size2);
	if(encryptedcontentbuf == NULL) 
	{ 
		printf("Error encryptedcontentbuf was NULL\n"); 
		logfile("Error encryptedcontentbuf was NULL\n"); 
		sleep(2); 
		exit(0); 
	}
	encrypt_buffer(index, buffer, encryptedcontentbuf, size2);
	free(buffer);


	logfile("Padding...\n");


	logfile("Writing...\n");
	u32 writeindex = 0;
	u32 restsize = size2;
	while (restsize > 0)
	{
		if (restsize >= SD_BLOCKSIZE)
		{
			retsize = fwrite(&(encryptedcontentbuf[writeindex]), 1, SD_BLOCKSIZE, f);
			restsize = restsize - SD_BLOCKSIZE;
			writeindex = writeindex + SD_BLOCKSIZE;
		} else
		{
			retsize = fwrite(&(encryptedcontentbuf[writeindex]), 1, restsize, f);
			restsize = 0;
		}

	}

	free(encryptedcontentbuf);
	header->data_len += size2;
	printf("Adding content done\n");
	logfile("Adding content done\n");
	return size2;
}	

void get_shared(FILE *f, u16 index, sha1 hash)
{
	u32 i;
	s32 ret;
	fstats *status = allocate_memory(sizeof(fstats) );
	printf("Adding shared content...");
	s32 fd = ISFS_Open("/shared1/content.map", ISFS_OPEN_READ);
	logfile("ISFS_Open(/shared1/content.map); returned %d\n", fd);
	ret = ISFS_GetFileStats(fd, status);
	if (ret < 0)
	{
		printf("\nISFS_GetFileStats(fd) returned %d\n", ret);
		logfile("ISFS_GetFileStats(fd) returned %d\n", ret);
		free(status);
		sleep(2);
		return;
		
	}	
	u32 fullsize = status->file_length;
	logfile("content.map is %u bytes\n", fullsize);
	u8 *out2 = allocate_memory(fullsize);
	u32 restsize = status->file_length;
	u32 retsize = 0;
	u32 writeindex = 0;
	u32 size = 0;
	while (restsize > 0)
	{
		if (restsize >= BLOCKSIZE)
		{
			size = BLOCKSIZE;
		} else
		{
			size = restsize;
		}
		ret = ISFS_Read(fd, &(out2[writeindex]), size);
		if (ret < 0)
		{
			printf("\nISFS_Read(%d, %d) returned %d\n", fd, size, ret);
			logfile("\nISFS_Read(%d, %d) returned %d\n", fd, size, ret);
			free(status);
			return;
		}
		writeindex = writeindex + size;
		restsize -= size;
	}
	ISFS_Close(fd);
	bool found = false;	
	for(i=8; i<fullsize; i+=0x1C) 
	{
	
		if(memcmp(out2+i, hash, 20) == 0)
		{
			char path[ISFS_MAXPATH];
			sprintf(path, "/shared1/%.8s.app", (out2+i)-8);
			logfile("Found shared content !\nPath is %s\n", path);
			u8 *out;
			u32 size_out = read_isfs(path, &out);
			
			u32 size2 = pad_data_32(out, size_out, &out);
			u8 *encryptedcontentbuf = allocate_memory(size2);
			if(encryptedcontentbuf == NULL) 
			{ 
				printf("\nError encryptedcontentbuf was NULL\n"); 
				logfile("Error encryptedcontentbuf was NULL\n"); 
				sleep(2); 
				exit(0); 
			}
			encrypt_buffer(index, out, encryptedcontentbuf, size2);
			free(out);
			retsize = 0;
			writeindex = 0;
			restsize = size2;
			while (restsize > 0)
			{
				if (restsize >= SD_BLOCKSIZE)
				{
					retsize = fwrite(&(encryptedcontentbuf[writeindex]), 1, SD_BLOCKSIZE, f);
					restsize = restsize - SD_BLOCKSIZE;
					writeindex = writeindex + SD_BLOCKSIZE;
				} else
				{
					retsize = fwrite(&(encryptedcontentbuf[writeindex]), 1, restsize, f);
					restsize = 0;
				}

			}
			header->data_len += size2;
			found = true;
			free(out2);
			free(encryptedcontentbuf);
			break;
		}
		
	}
	if(found == false)
	{
		printf("\nCould not find the shared content, no hash did match !\n");
		logfile("Could not find the shared content, no hash did match !\n");
		logfile("SHA1 of not found content:\n");
		hexdump_log(hash, 20);
		sleep(10);
		exit(0);
	}	
	printf("done\n");
}	

int isdir_sd(char *path)
{
	DIR* dir = opendir(path);
	if(dir == NULL)
		return 0;
	
	closedir(dir);

	return 1;
}

s32 getdir_sd(char *path, dirent_t **ent, u32 *cnt)
{
	u32 i = 0;
	DIR             *dip;
    struct dirent   *dit;
	char pbuf[ISFS_MAXPATH + 1];
	if ((dip = opendir(path)) == NULL)
    {
        printf("error opendir\n");
		logfile("error opendir\n");
        return 0;
    }
 
    while ((dit = readdir(dip)) != NULL)
    {
		//strcpy((*ent)[i].name, dit->d_name);
        i++;
        //printf("\n%s", dit->d_name);
    }
	closedir(dip);
	*ent = allocate_memory(sizeof(dirent_t) * i);
	i = 0;
	dip = opendir(path);
	if (dip == NULL)
    {
        printf("error opendir\n");
		logfile("error opendir\n");
        return 0;
    }
	logfile("SD DIR List of %s: \n\n", path);
    while ((dit = readdir(dip)) != NULL)
    {
		if(strncmp(dit->d_name, ".", 1) != 0 && strncmp(dit->d_name, "..", 2) != 0)
		{
					
			strcpy((*ent)[i].name, dit->d_name);
			sprintf(pbuf, "%s/%s", path, dit->d_name);
			logfile("%s\n", pbuf);
			(*ent)[i].type = ((isdir_sd(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
			
			i++;
			//printf("\n%s", dit->d_name);
		}	
    }
	closedir(dip);
	*cnt = i;
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	return 0;
}


s32 getdir_name(char *path, dirent_t **ent, u32 *cnt)
{
	s32 res;
	u32 num = 0;
	char pbuf[ISFS_MAXPATH + 1];

	int i, j, k;
	
	res = ISFS_ReadDir(path, NULL, &num);
	if(res != ISFS_OK)
	{
		printf("Error: could not get dir entry count! (result: %d)\n", res);
		logfile("Error: could not get dir entry count! (result: %d)\n", res);
		return -1;
	}

	char *nbuf = (char *)allocate_memory((ISFS_MAXPATH + 1) * num);
	char ebuf[ISFS_MAXPATH + 1];

	if(nbuf == NULL)
	{
		printf("Error: could not allocate buffer for name list!\n");
		logfile("Error: could not allocate buffer for name list!\n");
		return -1;
	}

	res = ISFS_ReadDir(path, nbuf, &num);
	if(res != ISFS_OK)
	{
		printf("Error: could not get name list! (result: %d)\n", res);
		logfile("Error: could not get name list! (result: %d)\n", res);
		return -1;
	}
	
	*cnt = num;
//	char name5[256];
	*ent = allocate_memory(sizeof(dirent_t) * num);
	logfile("ISFS DIR List of %s: \n\n", path);
	for(i = 0, k = 0; i < num; i++)
	{	    
		for(j = 0; nbuf[k] != 0; j++, k++)
			ebuf[j] = nbuf[k];
		ebuf[j] = 0;
		k++;
		//sprintf(name5, "%s", get_name(TITLE_ID(0x00010000, strtoll(ebuf, NULL, 16))));
		sprintf((*ent)[i].name, "%s", ebuf);
		sprintf(pbuf, "%s/%s", path, ebuf);
		logfile("%s\n", pbuf);
		(*ent)[i].type = ((isdir(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
		(*ent)[i].function = TYPE_UNKNOWN;
		if(strstr(path, "00010000") != 0)
		{
			(*ent)[i].function = TYPE_SAVEDATA;
		}
		if(strstr(path, "00010001") != 0)
		{
			(*ent)[i].function = TYPE_TITLE;
		}	
		if(strstr(path, "00000001") != 0)
		{
			(*ent)[i].function = TYPE_IOS;
			(*ent)[i].version = get_version(path, ebuf);
		}	
	}
	
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	free(nbuf);
	return 0;
}
s32 getdir_sd_name(char *path, dirent_t **ent, u32 *cnt)
{
	u32 i = 0;
	DIR             *dip;
    struct dirent   *dit;
	char pbuf[ISFS_MAXPATH + 1];
	if ((dip = opendir(path)) == NULL)
    {
        printf("error opendir\n");
		logfile("error opendir\n");
        return 0;
    }
 
    while ((dit = readdir(dip)) != NULL)
    {
		//strcpy((*ent)[i].name, dit->d_name);
        i++;
        //printf("\n%s", dit->d_name);
    }
	closedir(dip);
	*ent = allocate_memory(sizeof(dirent_t) * i);
	i = 0;
	dip = opendir(path);
	if (dip == NULL)
    {
        printf("error opendir\n");
		logfile("error opendir\n");
        return 0;
    }
	logfile("SD DIR List of %s: \n\n", path);
    while ((dit = readdir(dip)) != NULL)
    {
		if(strncmp(dit->d_name, ".", 1) != 0 && strncmp(dit->d_name, "..", 2) != 0)
		{
					
			strcpy((*ent)[i].name, dit->d_name);
			sprintf(pbuf, "%s/%s", path, dit->d_name);
			logfile("%s\n", pbuf);
			(*ent)[i].type = ((isdir_sd(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
			(*ent)[i].function = TYPE_UNKNOWN;
			if(strstr(path, "Savedata") != 0)
			{
				(*ent)[i].function = TYPE_SAVEDATA;
			}
			if(strstr(path, "WAD") != 0)
			{
				(*ent)[i].function = TYPE_TITLE;
			}		
			i++;
			//printf("\n%s", dit->d_name);
		}	
    }
	closedir(dip);
	*cnt = i;
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	return 0;
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
		printf("Error: could not get dir entry count! (result: %d)\n", res);
		logfile("Error: could not get dir entry count! (result: %d)\n", res);
		return -1;
	}

	char *nbuf = (char *)allocate_memory((ISFS_MAXPATH + 1) * num);
	char ebuf[ISFS_MAXPATH + 1];

	if(nbuf == NULL)
	{
		printf("Error: could not allocate buffer for name list!\n");
		logfile("Error: could not allocate buffer for name list!\n");
		return -1;
	}

	res = ISFS_ReadDir(path, nbuf, &num);
	if(res != ISFS_OK)
	{
		printf("Error: could not get name list! (result: %d)\n", res);
		logfile("Error: could not get name list! (result: %d)\n", res);
		return -1;
	}
	
	*cnt = num;
	
	*ent = allocate_memory(sizeof(dirent_t) * num);
	logfile("ISFS DIR List of %s: \n\n", path);
	for(i = 0, k = 0; i < num; i++)
	{	    
		for(j = 0; nbuf[k] != 0; j++, k++)
			ebuf[j] = nbuf[k];
		ebuf[j] = 0;
		k++;
		sprintf((*ent)[i].name, "%s", ebuf);
		sprintf(pbuf, "%s/%s", path, ebuf);
		logfile("%s\n", pbuf);
		(*ent)[i].type = ((isdir(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
		(*ent)[i].function = TYPE_UNKNOWN;
		if(strstr(path, "00010000") != 0)
		{
			(*ent)[i].function = TYPE_SAVEDATA;
		}
		if(strstr(path, "00010001") != 0)
		{
			(*ent)[i].function = TYPE_TITLE;
		}	
		if(strstr(path, "00000001") != 0)
		{
			(*ent)[i].function = TYPE_IOS;
			(*ent)[i].version = get_version(path, ebuf);
		}
	}
	
	qsort(*ent, *cnt, sizeof(dirent_t), __FileCmp);
	
	free(nbuf);
	return 0;
}
s32 getdir_sd_info(char *path, dirent_t **ent, u32 *cnt)
{
	u32 i = 0;
	DIR             *dip;
    struct dirent   *dit;
	char pbuf[ISFS_MAXPATH + 1];
	if ((dip = opendir(path)) == NULL)
    {
        printf("error opendir\n");
		logfile("error opendir\n");
        return 0;
    }
 
    while ((dit = readdir(dip)) != NULL)
    {
		//strcpy((*ent)[i].name, dit->d_name);
        i++;
        //printf("\n%s", dit->d_name);
    }
	closedir(dip);
	*ent = allocate_memory(sizeof(dirent_t) * i);
	i = 0;
	dip = opendir(path);
	if (dip == NULL)
    {
        printf("error opendir\n");
		logfile("error opendir\n");
        return 0;
    }
	logfile("SD DIR List of %s: \n\n", path);
    while ((dit = readdir(dip)) != NULL)
    {
		if(strncmp(dit->d_name, ".", 1) != 0 && strncmp(dit->d_name, "..", 2) != 0)
		{
					
			strcpy((*ent)[i].name, dit->d_name);
			sprintf(pbuf, "%s/%s", path, dit->d_name);
			logfile("%s\n", pbuf);
			(*ent)[i].type = ((isdir_sd(pbuf) == 1) ? DIRENT_T_DIR : DIRENT_T_FILE);
			(*ent)[i].function = TYPE_UNKNOWN;
			if(strstr(path, "Savedata") != 0)
			{
				(*ent)[i].function = TYPE_SAVEDATA;
			}
			if(strstr(path, "WAD") != 0)
			{
				(*ent)[i].function = TYPE_TITLE;
			}		
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
		printf("\nError: ISFS_OpenFile(%s) returned %d\n", source, fd);
		logfile("\nError: ISFS_OpenFile(%s) returned %d\n", source, fd);
		return fd;
	}
	
	if (!create_folders(destination))
	{
		printf("Error creating folder(s) for '%s'\n", destination);
		return -1;
	}

	file = fopen(destination, "wb");
	if (!file)
	{
		printf("\nError: fopen(%s) returned 0\n", destination);
		logfile("\nError: fopen(%s) returned 0\n", destination);
		ISFS_Close(fd);
		return -1;
	}
	
	status = memalign(32, sizeof(fstats) );
	ret = ISFS_GetFileStats(fd, status);
	if (ret < 0)
	{
		printf("\nISFS_GetFileStats(fd) returned %d\n", ret);
		logfile("\nISFS_GetFileStats(fd) returned %d\n", ret);
		ISFS_Close(fd);
		fclose(file);
		free(status);
		return ret;
	}
	Con_ClearLine();
	printf("Dumping file %s, size = %uKB", source, (status->file_length / 1024)+1);
	logfile("Dumping file %s, size = %uKB", source, (status->file_length / 1024)+1);
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
			printf("\nISFS_Read(%d, %p, %d) returned %d\n", fd, buffer, size, ret);
			logfile("\nISFS_Read(%d, %p, %d) returned %d\n", fd, buffer, size, ret);
			ISFS_Close(fd);
			fclose(file);
			free(status);
			free(buffer);
			return ret;
		}
		ret = fwrite(buffer, 1, size, file);
		if(ret < 0) 
		{
			printf("\nfwrite error%d\n", ret);
			logfile("\nfwrite error%d\n", ret);
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
	fseek(file, 0, SEEK_SET);
	printf("Flashing to %s\n", destination);
	logfile("Flashing to %s\n", destination);
	printf("SD file is %u bytes\n", filesize);	
	logfile("SD file is %u bytes\n", filesize);	

	ISFS_Delete(destination);
	ISFS_CreateFile(destination, 0, 3, 3, 3);
	nandfile = ISFS_Open(destination, ISFS_OPEN_RW);
	if(nandfile < 0)
	{
		printf("isfs_open_write error %d\n", nandfile);
		logfile("isfs_open_write error %d\n", nandfile);
		fclose(file);
		free(stats);
		free(buffer3);
		return -1;
	}
	printf("Writing file to nand...\n");
		
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
			printf(" fread error %d\n", ret);
			logfile(" fread error %d\n", ret);
		}
		ret = ISFS_Write(nandfile, buffer3, size);
		if(!ret) 
		{
			printf("isfs_write error %d\n", ret);
			logfile("isfs_write error %d\n", ret);
		}
		restsize -= size;
	}
	
	ISFS_Close(nandfile);
	nandfile = ISFS_Open(destination, ISFS_OPEN_RW);
	if(nandfile < 0)
	{
		printf("isfs_open_write error %d\n", nandfile);
		logfile("isfs_open_write error %d\n", nandfile);
		fclose(file);
		free(stats);
		free(buffer3);
		return -1;
	}	
	
	ret = ISFS_GetFileStats(nandfile, stats);
	printf("Flashing file to nand successful!\n");
	logfile("Flashing file to nand successful!\n");
	printf("New file is %u bytes\n", stats->file_length);
	ISFS_Close(nandfile);
	fclose(file);
	free(stats);
	free(buffer3);
	return 0;
}
bool dumpfolder(char source[1024], char destination[1024])
{
	//printf("Entering folder: %s\n", source);
	
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
	ret = getdir(fs_dirpath, &dir, &tcnt);
	if(ret == -1)
	{
		printf("ERROR on getdir_sd\n");
		logfile("ERROR on getdir_sd\n");
	}	

	
	remove(dirpath);
	/*
	ret = (u32)opendir(dirpath);
	if (ret == 0)
	{
		ret = mkdir(dirpath, 0777);
		if (ret < 0)
		{
			printf("Error making directory %d...\n", ret);
			logfile("Error making directory %d...\n", ret);
			free(dir);
			return false;
		}
	}
	*/
	for(i = 0; i < tcnt; i++) 
	{					
		sprintf(path, "%s/%s", fs_dirpath, dir[i].name);
		logfile("Source file is %s\n", path);
		
		if(dir[i].type == DIRENT_T_FILE) 
		{
			sprintf(path2, "%s/%s", dirpath, dir[i].name);
			logfile("Destination file is %s\n", path2);

			ret = dumpfile(path, path2);

		} else
		{
			if(dir[i].type == DIRENT_T_DIR) 
			{
				strcat(dirpath, "/");
				strcat(dirpath, dir[i].name);
				strcat(fs_dirpath, "/");
				strcat(fs_dirpath, dir[i].name);
				remove(dirpath);
				/*
				ret = (u32)opendir(dirpath);
				if (ret == 0)
				{
					ret = mkdir(dirpath, 0777);
					if (ret < 0)
					{
						printf("Error making directory %d...\n", ret);
						logfile("Error making directory %d...\n", ret);
						free(dirpath);
						return false;
					}
				}
				*/
				if (!dumpfolder(fs_dirpath, dirpath))
				{
					free(dir);
					return false;
				}
			}	
		}
	}
	free(dir);
	//printf("Dumping folder %s complete\n\n", source);
	return true;
}	
bool writefolder(char *source, char *temp, char *destination, char *path_out, bool savedata)
{
	//printf("Entering folder: %s\n", source);
	
	u32 tcnt;
	s32 ret;
	int i;
	bool found = false;
	char path[512];
	char path2[512];
	char dirpath[512];
	char sd_dirpath[512];
	char stuff[512];

	dirent_t *dir = NULL;

	strcpy(dirpath, destination);
	strcpy(sd_dirpath, source);
	if(savedata != true)
	{
		dirent_t *temp_dir = NULL;
		ret = getdir_sd(sd_dirpath, &temp_dir, &tcnt);
		if(ret == -1)
		{
			printf("ERROR on getdir_sd\n");
			logfile("ERROR on getdir_sd\n");
		}	

		for(i = 0; i < tcnt; i++) 
		{	
			if(strncmp(temp_dir[i].name + 5, temp, 4) == 0)
			{
				logfile("Found savedata ! %s\n", temp_dir[i].name);
				sprintf(sd_dirpath, "%s/%s", source, temp_dir[i].name);
				free(temp_dir);
				tcnt = 0;
				ret = getdir_sd(sd_dirpath, &dir, &tcnt);
				if(ret == -1)
				{
					printf("ERROR on getdir_sd\n");
					logfile("ERROR on getdir_sd\n");
				}	
				found = true;
				strcpy(stuff, sd_dirpath);
				//path_out = allocate_memory(strlen(stuff) + 10);
				//memset(path_out, 0, strlen(stuff) + 10);
				sprintf(path_out, "%s", stuff);

				break;
			}	
		}
	}	else
	{
		found = true;
		strcpy(stuff, sd_dirpath);
		ret = getdir_sd(sd_dirpath, &dir, &tcnt);
		if(ret == -1)
		{
			printf("ERROR on getdir_sd\n");
			logfile("ERROR on getdir_sd\n");
		}	
	}	
	if(found != true)
	{
		printf("Couldnt find the savedata on sd ! please extract the savedata first\n");
		logfile("Couldnt find the savedata on sd ! please extract the savedata first\n");
		sleep(5);
		free(dir);
		exit(0);
	}	
	if(isdir(dirpath) == 0)
	{
		//Need to fix recursive stuff i think ...
		ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
		logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
	} else
	{
		ret = ISFS_Delete(dirpath);
		logfile("ISFS_Delete(%s); %d\n", dirpath, ret);
		ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
		logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
	}	
	
	
	for(i = 0; i < tcnt; i++) 
	{				
		
		sprintf(path, "%s/%s", stuff, dir[i].name);
		logfile("Source file is %s\n", path);
		
		
		if(dir[i].type == DIRENT_T_FILE) 
		{
			sprintf(path2, "%s/%s", destination, dir[i].name);
			logfile("Destination file is %s\n", path2);

			ret = flash(path, path2);

		} else
		{
			if(dir[i].type == DIRENT_T_DIR) 
			{
				strcat(dirpath, "/");
				strcat(dirpath, dir[i].name);
				strcat(sd_dirpath, "/");
				strcat(sd_dirpath, dir[i].name);
				//ISFS_Delete(dirpath);
				//ISFS_CreateDir(dirpath, 0, 3, 3, 3);
				if(isdir(dirpath) == 0)
				{
					//Need to fix recursive stuff i think ...
					ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
					logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
				} else
				{
					ret = ISFS_Delete(dirpath);
					logfile("ISFS_Delete(%s); %d\n", dirpath, ret);
					ret = ISFS_CreateDir(dirpath, 0, 3, 3, 3);
					logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", dirpath, ret);
				}	
				char *random_buffer;
				random_buffer = allocate_memory(256);
				memset(random_buffer, 0, 256);
				if (!writefolder(sd_dirpath, temp, dirpath, random_buffer, true))
				{
					free(dir);
					return false;
				}
				free(random_buffer);
			}	
		}
	}
	free(dir);
	//printf("Dumping folder %s complete\n\n", source);
	return true;
}	



bool extract_savedata(u64 titleID)
{
	char path[ISFS_MAXPATH];
	char sd_path[MAXPATHLEN];
	char *temp;
	u32 low = TITLE_LOWER(titleID);
	bool succes = false;
	logfile("Extracting title %08x-%08x\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	temp = allocate_memory(6);
	memset(temp, 0, 6);
	memcpy(temp, (char *)(&low), 4);
	logfile("ID = %s\n", temp);
	sprintf(path, "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS Path is %s\n", path);
	if(TITLE_UPPER(titleID) == 0x00010000)
	{
		sprintf(sd_path, "sd:/BlueDump/Savedata/DISC %s - %s", temp, get_name(titleID));
		logfile("Savedata is disc savedata\n");
		logfile("SD Path is %s\n", sd_path);
	} else
	{
		sprintf(sd_path, "sd:/BlueDump/Savedata/WII_ %s - %s", temp, get_name(titleID));
		logfile("Savedata is wii savedata\n");
		logfile("SD Path is %s\n", sd_path);
	}	
	succes = dumpfolder(path, sd_path);
	sprintf(path, "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	strcat(sd_path, "/title.tmd");
	logfile("path = %s\n", path);
	logfile("sd_path = %s\n", sd_path);
	dumpfile(path, sd_path);
	return succes;
}	

bool install_savedata(u64 titleID)
{
	char path[ISFS_MAXPATH];
	char sd_path[MAXPATHLEN];
	char path_out[1024];
	char *temp;
	s32 ret;
	u32 low = TITLE_LOWER(titleID);
	bool succes = false;
	logfile("Installing title %08x-%08x\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	temp = allocate_memory(6);
	memset(temp, 0, 6);
	memcpy(temp, (char *)(&low), 4);
	logfile("ID = %s\n", temp);
	sprintf(path, "/title/%08x/%08x", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	if(isdir(path) == 0)
	{
		ret = ISFS_CreateDir(path, 0, 3, 3, 3);
		logfile("ISFS_CreateDir(%s, 0, 3, 3, 3); %d\n", path, ret);
	}
	sprintf(path, "/title/%08x/%08x/data", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	logfile("ISFS Path is %s\n", path);
	sprintf(sd_path, "sd:/BlueDump/Savedata");
	logfile("SD Path is %s\n", sd_path);
	succes = writefolder(sd_path, temp, path, path_out, false);
	sprintf(path, "/title/%08x/%08x/content/title.tmd", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	strcat(path_out, "/title.tmd");
	logfile("path_out = %s\n", path_out);
	logfile("path = %s\n", path);
	flash(path_out, path);
	return succes;
}	

void browser(char cpath[ISFS_MAXPATH + 1], dirent_t* ent, int cline, int lcnt, bool sd)
{
	int i;
	resetscreen();
	if(sd == false)
	{
		printf("BlueDump alpha 3\nPress 1 to see the options\nPress 2 to switch to SD\n\n");
	} else
	{
		printf("BlueDump alpha 3\nPress 1 to see the options\nPress 2 to switch to WII\n\n");
	}	
	//printf("Path: %s\n\n", cpath);
	printf("  NAME          \n");
		
	for(i = (cline / 15)*15; i < lcnt && i < (cline / 15)*15+15; i++) 
	{
		if (strncmp(cpath, "/title", 6) == 0 && strlen(cpath) == 6)
		{
			if (strncmp(ent[i].name, "00010000", 8) == 0)
			{
				//sprintf(ent[i].name, "%s - Savedata", ebuf);
				printf("%s %-12s - Disc Savedata\n", (i == cline ? ">" : " "), ent[i].name);
			} else
			if(strncmp(ent[i].name, "00010001", 8) == 0)
			{
				//sprintf(ent[i].name, "%s - Title's", ebuf);
				printf("%s %-12s - Titles\n", (i == cline ? ">" : " "), ent[i].name);
			} else
			if(strncmp(ent[i].name, "00000001", 8) == 0)
			{
				//sprintf(ent[i].name, "%s - IOS", ebuf);
				printf("%s %-12s - System Titles\n", (i == cline ? ">" : " "), ent[i].name);
			} else
			{
				printf("%s %-12s - ??? Titles\n", (i == cline ? ">" : " "), ent[i].name);
			}
		} else
		if (strncmp(cpath, "/title/00000001", 15) == 0 && strlen(cpath) == 15)
		{
			if (strncmp(ent[i].name, "00000001", 8) == 0)
			{
				printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, "BOOT2");
			} else
			if (strncmp(ent[i].name, "00000002", 8) == 0)
			{
				printf("%s %-12s - %s v%u\n", (i == cline ? ">" : " "), ent[i].name, "System menu", ent[i].version);
			} else
			if (strncmp(ent[i].name, "00000100", 8) == 0)
			{
				printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, "BC");
			} else
			if (strncmp(ent[i].name, "00000101", 8) == 0)
			{
				printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, "MIOS");
			} else
			if (strncmp(ent[i].name, "00000000", 8) == 0)
			{
				printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, "???");
			} else
			{
				printf("%s %-12s - %s%u v%u\n", (i == cline ? ">" : " "), ent[i].name, "IOS", (u32)strtol(ent[i].name,NULL,16), ent[i].version);
			}		
		} else
		{
			//sprintf(ent[i].name, "%s", ebuf);
			if(sd == false)
			{
				if(ent[i].function == TYPE_SAVEDATA)
				{
					printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, get_name(TITLE_ID(0x00010000, strtoll(ent[i].name, NULL, 16))));
				} else
				if(ent[i].function == TYPE_TITLE)
				{
					printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, get_name(TITLE_ID(0x00010001, strtoll(ent[i].name, NULL, 16))));
				} else
				{
					printf("%s %-12s\n", (i == cline ? ">" : " "), ent[i].name);
				}	
			} else
			{
				
				printf("%s %-12s\n", (i == cline ? ">" : " "), ent[i].name);
				
			}	
			
		}	
		//printf("%s %-12s\n", (i == cline ? ">" : " "), ent[i].name);
				
	}
	printf("\n");
}
void browser_sd_info(char cpath[ISFS_MAXPATH + 1], dirent_t* ent, int cline, int lcnt, bool sd)
{
	int i;
	resetscreen();
	if(sd == false)
	{
		printf("BlueDump alpha 3\nPress 1 to see the options\nPress 2 to switch to SD\n\n");
	} else
	{
		printf("BlueDump alpha 3\nPress 1 to see the options\nPress 2 to switch to WII\n\n");
	}
	//printf("Path: %s\n\n", cpath);
	printf("  NAME          \n");
		
	for(i = (cline / 15)*15; i < lcnt && i < (cline / 15)*15+15; i++) 
	{
		if(strncmp(ent[i].name, "Savedata", 8) == 0)
		{
			//sprintf(ent[i].name, "%s - Savedata", ebuf);
			printf("%s %-12s - Savedata\n", (i == cline ? ">" : " "), ent[i].name);
		} else
		if(strncmp(ent[i].name, "WAD", 8) == 0)
		{
			//sprintf(ent[i].name, "%s - Title's", ebuf);
			printf("%s %-12s - WAD\n", (i == cline ? ">" : " "), ent[i].name);
		} else
		{
			//sprintf(ent[i].name, "%s", ebuf);
			if(sd == false)
			{
				if(ent[i].function == TYPE_SAVEDATA)
				{
					printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, get_name(TITLE_ID(0x00010000, strtoll(ent[i].name, NULL, 16))));
				} else
				if(ent[i].function == TYPE_TITLE)
				{
					printf("%s %-12s - %s\n", (i == cline ? ">" : " "), ent[i].name, get_name(TITLE_ID(0x00010001, strtoll(ent[i].name, NULL, 16))));
				} else
				{
					printf("%s %-12s\n", (i == cline ? ">" : " "), ent[i].name);
				}	
			} else
			{
				
				printf("%s %-12s\n", (i == cline ? ">" : " "), ent[i].name);
				
			}
			
		}	
		//printf("%s %-12s\n", (i == cline ? ">" : " "), ent[i].name);
				
	}
	printf("\n");
}

void make_header()
{
	wadHeader *now = allocate_memory(sizeof(wadHeader));
	if(now == NULL) 
	{
		printf("Error allocating memory for wadheader\n"); 
		logfile("Error allocating memory for wadheader\n");
		sleep(2); 
		exit(0); 
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

void get_title_key(signed_blob *s_tik, u8 *key) {
	static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);

	const tik *p_tik;
	p_tik = (tik *)SIGNATURE_PAYLOAD(s_tik);
	u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
	memcpy(keyin, enc_key, sizeof keyin);
	logfile("Encrypted Title key = \n");
	hexdump_log(keyin, sizeof keyin);
	logfile("\n\n");

	memset(keyout, 0, sizeof keyout);

	memset(iv, 0, sizeof iv);

	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);
  
	aes_set_key(commonkey);
	aes_decrypt(iv, keyin, keyout, sizeof keyin);
	memcpy(key, keyout, sizeof keyout);
	logfile("Decrypted Title key = \n");
	hexdump_log(keyout, sizeof keyout);
	logfile("\n\n");
}



s32 Wad_Dump(u64 id, char *path)
{
	make_header();
	
	logfile("Started WAD Packing...\nPacking Title %08x-%08x\n", TITLE_UPPER(id), TITLE_LOWER(id));

	signed_blob *p_tik = NULL;
	signed_blob *p_tmd = NULL;
	
	tmd *tmd_data  = NULL;
	u8 key[16];
	
	u32 cnt = 0;
	
	FILE *wadout;
	logfile("WAD_Dump path = %s\n", path);
	if (!create_folders(path))
	{
		printf("Error creating folder(s) for '%s'\n", path);
		sleep(5);
		return -1;
	}

	wadout = fopen(path, "wb");
	if (!wadout)
	{
		printf("fopen error\n");
		logfile("fopen error\n");
		sleep(5);
		exit(0);	
	}
	
	u8 *padding_table = allocate_memory(64);
	if (padding_table == NULL)
	{
		printf("Out of memory\n");
		logfile("Out of memory\n");
		sleep(5);
		exit(0);	
	}
	
	memset(padding_table, 0, 64);
	fwrite(padding_table, 1, 64, wadout);
	free(padding_table);

	printf("Reading Certs... ");
	logfile("Reading Certs... ");
	fflush(stdout);
	
	header->certs_len = GetCert(wadout);	
	printf("done\n");
	logfile("done\n");
	check_not_0(header->certs_len, "Error getting Certs\n");
	printf("Reading Ticket... ");
	logfile("Reading Ticket... ");
	//sleep(1);
	header->tik_len = GetTicket(wadout, id, &p_tik);
	printf("done\n");
	logfile("done\n");
	check_not_0(header->tik_len, "Error getting Ticket\n");
	printf("Reading TMD... ");
	logfile("Reading TMD... ");
	header->tmd_len = GetTMD(wadout, id, &p_tmd);
	printf("done\n");
	logfile("done\n");
	check_not_0(header->tmd_len, "Error getting TMD\n");
	printf("Decrypting AES Title Key... ");
	logfile("Decrypting AES Title Key... ");

	get_title_key(p_tik, (u8 *)key);
	aes_set_key(key);
	printf("done\n");
	logfile("done\n");

	tmd_data = (tmd *)SIGNATURE_PAYLOAD(p_tmd);
	
	for (cnt = 0; cnt < tmd_data->num_contents; cnt++) 
	{
		printf("Processing content %u\n", cnt);
		logfile("Processing content %u\n", cnt);
		tmd_content *content = &tmd_data->contents[cnt];

		u32 len2 = 0;
		
		u16 type = 0;

		type = content->type;
		switch(type)
		{
			case 0x0001:
				len2 = GetContent(wadout, id, content->cid, content->index, false);
				check_not_0(len2, "Error reading content\n");
				break;	
			case 0x8001:
				//len2 = GetContent(wadout, id, content->cid, content->index, true);
				//check_not_0(len2, "Error reading content\n");
				get_shared(wadout, content->index, content->hash);
				break;
			default:
				printf("Unknown Content Type  %04x... Aborting\n", type);
				logfile("Unknown Content Type  %04x... Aborting\n", type);
				sleep(5);
				exit(-1);
				break;
		}				
	}

	printf("Adding Header... ");
	logfile("Adding Header... ");
	fseek(wadout, 0, SEEK_SET);

	fwrite((u8 *)header, 1, 0x20, wadout);
	printf("done\n");
	logfile("done\n");
	logfile("Hexdump of header :\n");
	hexdump_log(header, 0x20);
	logfile("\n\n");
	fclose(wadout);	
	free(header);
		
	return 0;
}
u64 copy_id(char *path)
{

	char *low_out = allocate_memory(10);
	memset(low_out, 0, 10);
	char *high_out = allocate_memory(10);
	memset(high_out, 0, 10);	
	
	/*
	int i = 0;
	while(i < 8)
	{
		high[i] = path[7 + i];
		i++;
	}	
	i = 0;	
	*/
	/*while(i < 8)
	{
		low_out[i] = path[16 + i];
		i++;
	}	*/
	strncpy(high_out, path+7, 8);
	strncpy(low_out, path+16, 8);

	u64 titleID = TITLE_ID(strtol(high_out, NULL, 16), strtol(low_out,NULL,16));
	logfile("generated copy_id id was %08x-%08x\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));
	free(low_out);
	free(high_out);
	return titleID;
}
u64 copy_id_sd_save(char *path, bool disc)
{

	u32 low = 0;
	
	u64 titleID;
	memcpy(&low, path+27, 4);
		
	logfile("copy_id_sd_save low = %08x\n", low);
	if(disc == true)
	{
		logfile("copy_id_sd_save disc = true\n");
		titleID = TITLE_ID(0x00010000, low);
	} else
	{
		logfile("copy_id_sd_save disc = false\n");
		titleID = TITLE_ID(0x00010001, low);
	}
	logfile("generated copy_id_sd_save id was %08x-%08x\n", TITLE_UPPER(titleID), TITLE_LOWER(titleID));

	return titleID;
}
void set_highlight(bool highlight)
{
	if (highlight)
	{
		printf("\x1b[%u;%um", 47, false);
		printf("\x1b[%u;%um", 30, false);
	} else
	{
		printf("\x1b[%u;%um", 37, false);
		printf("\x1b[%u;%um", 40, false);
	}
}

void dump_menu(char *cpath, char *tmp, int cline, int lcnt, dirent_t *ent)
{

	char some[500];
	char *options[3] = { "Backup Savedata >", "< Restore Savedata >" , "< Backup to WAD"};
	int selection = 0;
	
	resetscreen();
	printf("Select what to do\n\n");
		
	while(true)
	{
	
		set_highlight(true);
		printf("\t%s\r", options[selection]);
		set_highlight(false);
		WPAD_ScanPads();
		u32 pressed = WPAD_ButtonsDown(0);
	
		if (pressed == WPAD_BUTTON_LEFT)
		{	
			if (selection > 0)
			{
				selection--;
			} else
			{
				selection = 2;
			}
			resetscreen();
			printf("Select what to do\n\n");
		}

		if (pressed == WPAD_BUTTON_RIGHT)
		{	
			if (selection < 2)
			{
				selection++;
			} else
			{
				selection = 0;
			}
			resetscreen();
			printf("Select what to do\n\n");
		}
		if(pressed == WPAD_BUTTON_A)
		{
			break;
		}	
	}
	
	
	strcpy(tmp, cpath);
	if(strcmp(cpath, "/") != 0)
	{
		sprintf(some, "%s/%s", tmp, ent[cline].name);
	} else
	{				
		sprintf(some, "/%s", ent[cline].name);
	}
	//getdir(cpath, &ent, &lcnt);
	//cline = 0;
			
	logfile("cline :%s\n", some);
	switch(selection)
	{
		case 0:
			printf("Backing up savedata ...\n");
			logfile("Backing up savedata ...\n");
			u64 titleID = copy_id(some);
			extract_savedata(titleID);
			printf("done\n");
			logfile("done\n");
			break;
		case 1:
			printf("Restoring savedata ...\n");
			logfile("Restoring savedata ...\n");
			u64 titleID2 = copy_id(some);
			install_savedata(titleID2);
			printf("done\n");
			logfile("done\n");
			break;	
		case 2:
			if(ent[cline].function == TYPE_TITLE)
			{
				printf("Creating WAD ...          \n");
				logfile("Creating WAD ...         \n");
				char idtext[10];
				char testid[256];
				strncpy(idtext, ent[cline].name, 8);
				sprintf(testid, "sd:/BlueDump/WAD/00010001-");
				strncat(testid, idtext, 8);
				strncat(testid, ".wad", 4);
				logfile("Path for dump = %s\n", testid);
				Wad_Dump(TITLE_ID(0x00010001, strtoll(idtext, NULL, 16)), testid);
				printf("done\n");
				logfile("done\n");
				
			} else
			if(ent[cline].function == TYPE_IOS)
			{
				printf("Creating WAD ...                 \n");
				logfile("Creating WAD ...                \n");
				char buf[6];
				char idtext[10];
				char testid[256];
				strncpy(idtext, ent[cline].name, 8);
				sprintf(testid, "sd:/BlueDump/WAD/00000001-");
				strncat(testid, idtext, 8);
				if(strncmp(ent[cline].name, "00000002", 8) ==0)
				{
					sprintf(buf, " - SystemMenu v%u", ent[cline].version);
					strncat(testid,  buf, strlen(buf));
					//sprintf(buf, "%u", (u32)strtol(ent[cline].name,NULL,16));
					//strncat(testid,  buf, strlen(buf));
					strncat(testid, ".wad", 4);
				} else
				{
					strncat(testid, " - IOS", 6);
					sprintf(buf, "%u v%u", (u32)strtol(ent[cline].name,NULL,16), ent[cline].version);
					strncat(testid,  buf, strlen(buf));
					strncat(testid, ".wad", 4);
				}
				logfile("Path for dump = %s\n", testid);
				Wad_Dump(TITLE_ID(0x00000001, strtoll(idtext, NULL, 16)), testid);
				printf("done\n");
				logfile("done\n");
				
			} else
			{
				printf("This is not a title ! Use the savedata functions for this\n");
				sleep(3);
				
			}	
			break;
		/*case TYPE_IOS:
			printf("Dumping IOS ...\n");
			logfile("Dumping IOS ...\n");
			char idtext2[10];
			char testid2[256];
			strncpy(idtext2, ent[cline].name, 8);
			sprintf(testid2, "sd:/BlueDump/WAD/00000001-");
			strncat(testid2, idtext2, 8);
			strncat(testid2, ".wad", 4);
			logfile("Path for dump = %s\n", testid2);
			Wad_Dump(TITLE_ID(0x00000001, strtoll(idtext2, NULL, 16)), testid2);
			printf("done\n");
			logfile("done\n");
			break;*/
		default:
			break;
	}
	browser(cpath, ent, cline, lcnt, false);
}
void dump_menu_sd(char *cpath, char *tmp, int cline, int lcnt, dirent_t *ent)
{

	char some[500];
	char *options[2] = { "Backup Savedata >", "< Restore Savedata >"};
	int selection = 0;
	
	resetscreen();
	printf("Select what to do\n\n");
		
	while(true)
	{
	
		set_highlight(true);
		printf("\t%s\r", options[selection]);
		set_highlight(false);
		WPAD_ScanPads();
		u32 pressed = WPAD_ButtonsDown(0);
	
		if (pressed == WPAD_BUTTON_LEFT)
		{	
			if (selection > 0)
			{
				selection--;
			} else
			{
				selection = 1;
			}
			resetscreen();
			printf("Select what to do\n\n");
		}

		if (pressed == WPAD_BUTTON_RIGHT)
		{	
			if (selection < 1)
			{
				selection++;
			} else
			{
				selection = 0;
			}
			resetscreen();
			printf("Select what to do\n\n");
		}
		if(pressed == WPAD_BUTTON_A)
		{
			break;
		}	
	}
	
	
	strcpy(tmp, cpath);

	sprintf(some, "%s/%s", tmp, ent[cline].name);

	
	//getdir(cpath, &ent, &lcnt);
	//cline = 0;
			
	logfile("cline :%s\n", some);
	u64 titleID;
	u64 titleID2;
	switch(selection)
	{
		case 0:
			printf("Backing up savedata ...\n");
			logfile("Backing up savedata ...\n");
			if(strstr(some, "DISC") != 0)
			{
				titleID = copy_id_sd_save(some, true);
				logfile("Savedata is disc savedata\n");
			} else	
			{
				titleID = copy_id_sd_save(some, false);
				logfile("Savedata is wii savedata\n");
			}
			extract_savedata(titleID);
			printf("done\n");
			logfile("done\n");
			break;
		case 1:
			printf("Restoring savedata ...\n");
			logfile("Restoring savedata ...\n");
			if(strstr(some, "DISC") != 0)
			{
				titleID2 = copy_id_sd_save(some, true);
				logfile("Savedate is disc savedata\n");
			} else	
			{
				titleID2 = copy_id_sd_save(some, false);
				logfile("Savedate is wii savedata\n");
			}
			install_savedata(titleID2);
			printf("done\n");
			logfile("done\n");
			break;	
		default:
			break;
	}
	browser(cpath, ent, cline, lcnt, true);
}
void sd_browser()
{
	resetscreen();
	printf("BlueDump alpha 3\nPress 1 to see the options\nPress 2 to switch to WII\n\n");
	
	int i = 0;
	char tmp[ISFS_MAXPATH + 1];
	char cpath[ISFS_MAXPATH + 1];	
	dirent_t* ent = NULL;
	u32 lcnt = 0;
	u32 cline = 0;
	sprintf(cpath, "sd:/BlueDump");
	getdir_sd_info(cpath, &ent, &lcnt);
	cline = 0;
	browser_sd_info(cpath, ent, cline, lcnt, true);
	
	while (1) 
	{

		WPAD_ScanPads();
		u32 buttonsdown = WPAD_ButtonsDown(0);


		//Navigate up.
		if (buttonsdown & WPAD_BUTTON_UP)
		{			
			if(cline > 0) 
			{
				cline--;
			} else
			{
				cline = lcnt - 1;
			}
			browser_sd_info(cpath, ent, cline, lcnt, true);
		}

		//Navigate down.
		if (buttonsdown & WPAD_BUTTON_DOWN)
		{
			if(cline < (lcnt - 1))
			{
				cline++;
			} else
			{
				cline = 0;
			}
			browser_sd_info(cpath, ent, cline, lcnt, true);
		}

		//Enter parent dir.
		if (buttonsdown & WPAD_BUTTON_B)
		{
			int len = strlen(cpath);
			for(i = len; cpath[i] != '/'; i--);
			if(i == 0)
				strcpy(cpath, "sd:/BlueDump");
			else
				cpath[i] = 0;
				
			if(strcmp(cpath + 13, "WAD") == 0)
			{
				if(strcmp(cpath + 16, "/") != 0)
				{
					getdir_sd_name(cpath, &ent, &lcnt);
				}	
			} else
			{
				getdir_sd_info(cpath, &ent, &lcnt);
			}	
			cline = 0;
			
			browser_sd_info(cpath, ent, cline, lcnt, true);
		}

		//Enter dir.
		if (buttonsdown & WPAD_BUTTON_A)
		{
			//Is the current entry a dir?
			if(ent[cline].type == DIRENT_T_DIR)
			{
				strcpy(tmp, cpath);
				if(strcmp(cpath, "/") != 0)
				{
					sprintf(cpath, "%s/%s", tmp, ent[cline].name);
				} else
				{				
					sprintf(cpath, "/%s", ent[cline].name);
				}
				//getdir_name(cpath, &ent, &lcnt);
				if(strcmp(cpath + 13, "WAD") == 0)
				{
					if(strcmp(cpath + 16, "/") != 0)
					{
						getdir_sd_name(cpath, &ent, &lcnt);
					}	
				} else
				{
					getdir_sd_info(cpath, &ent, &lcnt);
				}
				cline = 0;
				printf("cline :%s\n", cpath);
				/*sprintf(path3, "sd:/FSTOOLBOX%s", cpath);
				ret = (u32)opendir(path3);
				if (ret == 0)
				{
					printf("Folder %s does not exist, making it...\n", path3);
					ret = mkdir(path3, 0777);
					if (ret < 0)
					{
						printf("Error making directory %d...\n", ret);
						sleep(10);
						Reboot();
					}
				}*/
			}
			browser_sd_info(cpath, ent, cline, lcnt, true);
		}
		if (buttonsdown & WPAD_BUTTON_1)
		{
			/*//Is the current entry a dir?
			if(ent[cline].type == DIRENT_T_DIR)
			{
				strcpy(tmp, cpath);
				if(strcmp(cpath, "/") != 0)
				{
					sprintf(some, "%s/%s", tmp, ent[cline].name);
				} else
				{				
					sprintf(some, "/%s", ent[cline].name);
				}
				//getdir(cpath, &ent, &lcnt);
				//cline = 0;
				
				logfile("cline :%s\n", some);
				switch(ent[cline].function)
				{
					case TYPE_SAVEDATA:
						printf("Extracting savedata ...\n");
						logfile("Extracting savedata ...\n");
						u64 titleID = copy_id(some);
						extract_savedata(titleID);
						printf("done\n");
						logfile("done\n");
						break;
					case TYPE_TITLE:
						printf("Dumping title ...\n");
						logfile("Dumping title ...\n");
						char idtext[10];
						char testid[256];
						strncpy(idtext, ent[cline].name, 8);
						sprintf(testid, "sd:/BlueDump/WAD/00010001-");
						strncat(testid, idtext, 8);
						strncat(testid, ".wad", 4);
						logfile("Path for dump = %s\n", testid);
						Wad_Dump(TITLE_ID(0x00010001, strtoll(idtext, NULL, 16)), testid);
						printf("done\n");
						logfile("done\n");
						break;
					case TYPE_IOS:
						printf("Dumping IOS ...\n");
						logfile("Dumping IOS ...\n");
						char idtext2[10];
						char testid2[256];
						strncpy(idtext2, ent[cline].name, 8);
						sprintf(testid2, "sd:/BlueDump/WAD/00000001-");
						strncat(testid2, idtext2, 8);
						strncat(testid2, ".wad", 4);
						logfile("Path for dump = %s\n", testid2);
						Wad_Dump(TITLE_ID(0x00000001, strtoll(idtext2, NULL, 16)), testid2);
						printf("done\n");
						logfile("done\n");
						break;
				}		
				//printf("done\n");
				sprintf(path3, "sd:/FSTOOLBOX%s", cpath);
				ret = (u32)opendir(path3);
				if (ret == 0)
				{
					printf("Folder %s does not exist, making it...\n", path3);
					ret = mkdir(path3, 0777);
					if (ret < 0)
					{
						printf("Error making directory %d...\n", ret);
						sleep(10);
						Reboot();
					}
				}
			}
			//browser(cpath, ent, cline, lcnt);
			*/
			dump_menu_sd(cpath, tmp, cline, lcnt, ent);
		}

		if (buttonsdown & WPAD_BUTTON_HOME)
		{
			exit(0);
		}
		if (buttonsdown & WPAD_BUTTON_2)
		{
			break;
		}
	
	}
	lcnt = 0;
	cline = 0;
	sprintf(cpath, "/title");
	getdir_info(cpath, &ent, &lcnt);
	resetscreen();
	browser(cpath, ent, cline, lcnt, false);
}	
int main(int argc, char* argv[])
{
	int ret;
	videoInit();
	int i = 0;
	IOS_ReloadIOS(249);

	ISFS_Initialize();
	WPAD_Init();
	WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);
	ret = __io_wiisd.startup();
	if (ret < 0)
	{
		printf("SD error\n");
	
		sleep(5);
		exit(0);
	}
	ret = fatMountSimple("sd", &__io_wiisd);
	if (ret < 0)
	{
		printf("FAT error\n");

		sleep(5);
		exit(0);
	}
	sleep(1);
	reset_log();
	//initFTP("save:/");
	//mkdir("sd:/BlueDump", 0777);
	//mkdir("sd:/BlueDump/WAD", 0777);
	//mkdir("sd:/BlueDump/Savedata", 0777);
	//Wad_Dump(0x0000000100000002LL, "sd:/BlueDump/WAD/sysmenu.wad");

	//printf("Packing complete\n");
	//logfile("Packing complete\n");
	//extract_savedata(0x0001000053584150LL);
	//install_savedata(0x0001000053584150LL);
	//install_savedata_ftp(0x0001000053584150LL);
	//parse_db(NULL, NULL, NULL);
	//char path2[500];
//	char path3[500];
	printf("BlueDump alpha 3\nPress 1 to see the options\nPress 2 to switch to SD\n\n");

	char tmp[ISFS_MAXPATH + 1];
	char cpath[ISFS_MAXPATH + 1];	
	dirent_t* ent = NULL;
	u32 lcnt = 0;
	u32 cline = 0;
	sprintf(cpath, "/title");
	getdir_info(cpath, &ent, &lcnt);
	cline = 0;
	browser(cpath, ent, cline, lcnt, false);
	
	while (1) 
	{

		WPAD_ScanPads();
		u32 buttonsdown = WPAD_ButtonsDown(0);


		//Navigate up.
		if (buttonsdown & WPAD_BUTTON_UP)
		{			
			if(cline > 0) 
			{
				cline--;
			} else
			{
				cline = lcnt - 1;
			}
			browser(cpath, ent, cline, lcnt, false);
		}

		//Navigate down.
		if (buttonsdown & WPAD_BUTTON_DOWN)
		{
			if(cline < (lcnt - 1))
			{
				cline++;
			} else
			{
				cline = 0;
			}
			browser(cpath, ent, cline, lcnt, false);
		}

		//Enter parent dir.
		if (buttonsdown & WPAD_BUTTON_B)
		{
			int len = strlen(cpath);
			for(i = len; cpath[i] != '/'; i--);
			if(i == 0)
				strcpy(cpath, "/title");
			else
				cpath[i] = 0;
				
			if(strcmp(cpath + 7, "00010000") == 0)
			{
				if(strcmp(cpath + 15, "/") != 0)
				{
					getdir_name(cpath, &ent, &lcnt);
				}	
			} else
			{
				getdir_info(cpath, &ent, &lcnt);
			}	
			cline = 0;
			browser(cpath, ent, cline, lcnt, false);
		}

		//Enter dir.
		if (buttonsdown & WPAD_BUTTON_A)
		{
			//Is the current entry a dir?
			if(ent[cline].type == DIRENT_T_DIR)
			{
				strcpy(tmp, cpath);
				if(strcmp(cpath, "/") != 0)
				{
					sprintf(cpath, "%s/%s", tmp, ent[cline].name);
				} else
				{				
					sprintf(cpath, "/%s", ent[cline].name);
				}
				//getdir_name(cpath, &ent, &lcnt);
				if(strcmp(cpath + 7, "00010000") == 0)
				{
					if(strcmp(cpath + 15, "/") != 0)
					{
						getdir_name(cpath, &ent, &lcnt);
					}	
				} else
				{
					getdir_info(cpath, &ent, &lcnt);
				}
				cline = 0;
				printf("cline :%s\n", cpath);
				/*sprintf(path3, "sd:/FSTOOLBOX%s", cpath);
				ret = (u32)opendir(path3);
				if (ret == 0)
				{
					printf("Folder %s does not exist, making it...\n", path3);
					ret = mkdir(path3, 0777);
					if (ret < 0)
					{
						printf("Error making directory %d...\n", ret);
						sleep(10);
						Reboot();
					}
				}*/
			}
			browser(cpath, ent, cline, lcnt, false);
		}
		if (buttonsdown & WPAD_BUTTON_1)
		{
			/*//Is the current entry a dir?
			if(ent[cline].type == DIRENT_T_DIR)
			{
				strcpy(tmp, cpath);
				if(strcmp(cpath, "/") != 0)
				{
					sprintf(some, "%s/%s", tmp, ent[cline].name);
				} else
				{				
					sprintf(some, "/%s", ent[cline].name);
				}
				//getdir(cpath, &ent, &lcnt);
				//cline = 0;
				
				logfile("cline :%s\n", some);
				switch(ent[cline].function)
				{
					case TYPE_SAVEDATA:
						printf("Extracting savedata ...\n");
						logfile("Extracting savedata ...\n");
						u64 titleID = copy_id(some);
						extract_savedata(titleID);
						printf("done\n");
						logfile("done\n");
						break;
					case TYPE_TITLE:
						printf("Dumping title ...\n");
						logfile("Dumping title ...\n");
						char idtext[10];
						char testid[256];
						strncpy(idtext, ent[cline].name, 8);
						sprintf(testid, "sd:/BlueDump/WAD/00010001-");
						strncat(testid, idtext, 8);
						strncat(testid, ".wad", 4);
						logfile("Path for dump = %s\n", testid);
						Wad_Dump(TITLE_ID(0x00010001, strtoll(idtext, NULL, 16)), testid);
						printf("done\n");
						logfile("done\n");
						break;
					case TYPE_IOS:
						printf("Dumping IOS ...\n");
						logfile("Dumping IOS ...\n");
						char idtext2[10];
						char testid2[256];
						strncpy(idtext2, ent[cline].name, 8);
						sprintf(testid2, "sd:/BlueDump/WAD/00000001-");
						strncat(testid2, idtext2, 8);
						strncat(testid2, ".wad", 4);
						logfile("Path for dump = %s\n", testid2);
						Wad_Dump(TITLE_ID(0x00000001, strtoll(idtext2, NULL, 16)), testid2);
						printf("done\n");
						logfile("done\n");
						break;
				}		
				//printf("done\n");
				sprintf(path3, "sd:/FSTOOLBOX%s", cpath);
				ret = (u32)opendir(path3);
				if (ret == 0)
				{
					printf("Folder %s does not exist, making it...\n", path3);
					ret = mkdir(path3, 0777);
					if (ret < 0)
					{
						printf("Error making directory %d...\n", ret);
						sleep(10);
						Reboot();
					}
				}
			}
			//browser(cpath, ent, cline, lcnt);
			*/
			dump_menu(cpath, tmp, cline, lcnt, ent);
		}

		if (buttonsdown & WPAD_BUTTON_HOME)
		{
			exit(0);
		}
			if (buttonsdown & WPAD_BUTTON_2)
		{
			sd_browser();
		}
	
	}
	
	sleep(2);
	fatUnmount("sd");
	__io_wiisd.shutdown();

	exit(0);
}	
	
