#ifndef __YABDM_H__
#define __YABDM_H__

#define BLOCKSIZE		0x4000 // 16 KB
#define SD_BLOCKSIZE	0x8000 // 32 KB

#define DIRENT_T_FILE 0
#define DIRENT_T_DIR 1

#define ROOT_DIR "/title"
#define SD_ROOT_DIR "sd:/private/wii/title"
#define DEVICE(x) (((x) == 0) ? (isSD ? "sd" : "usb") : (isSD ? "SD" : "USB"))

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
#define round64(x)      round_up((x),0x40)
#define round16(x)		round_up((x),0x10)

#define MAX_CHARACTERS(x) ((sizeof((x))) / (sizeof((x)[0]))) // Returns the number of elements in an array

#define ARROW " \x10"

typedef struct _dirent
{
	char name[ISFS_MAXPATH + 1];
	u16 version;
	int type;
	int function;
	char titlename[ISFS_MAXPATH + 1];
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

typedef struct map_entry
{
	char filename[8];
	u8 sha1[20];
} __attribute__((packed)) map_entry_t;

map_entry_t *cm;
size_t content_map_size;
size_t content_map_items;

void yabdm_loop(void);

#endif /* __YABDM_H__ */
