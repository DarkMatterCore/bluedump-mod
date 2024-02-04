#ifndef __YABDM_H__
#define __YABDM_H__

#define BLOCKSIZE		0x4000 // 16 KB
#define SD_BLOCKSIZE	0x8000 // 32 KB

#define DIRENT_T_FILE	0
#define DIRENT_T_DIR	1

#define ROOT_DIR		"/title"
#define SD_ROOT_DIR		"sd:/private/wii/title"

#define TYPE_SAVEDATA 	0
#define TYPE_TITLE 		1
#define TYPE_IOS		2
#define TYPE_SYSTITLE	3
#define TYPE_GAMECHAN	4
#define TYPE_DLC		5
#define TYPE_HIDDEN		6
#define TYPE_OTHER 		7

#define round_up(x,n)   (-(-(x) & -(n)))
#define round64(x)      round_up((x),0x40)
#define round16(x)		round_up((x),0x10)

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

/* Taken from Wiibrew */
typedef struct
{
	u8 header[64];		// Header
	u8 zeroes[64];		// Padding
	u32 imet;			// "IMET" magic word
	u32 hashsize;		// Hash length
	u32 unk;			// 3 fixed, unknown purpose. Possibly file count?
	u32 sizes[3];		// icon.bin, banner.bin, sound.bin
	u32 flag1;			// unknown
	u8 names[20][42];	// Japanese, English, German, French, Spanish, Italian, Dutch, Simp. Chinese, Trad. Chinese, Korean
	u8 lol[0xC];
} IMET;

typedef struct
{
	u32 wibn;			// "WIBN" magic word
	u32 flags;			// Title flags
	u16 speed;			// Animation speed
	u8 zeroes[22];		// Padding
	u8 name[64];		// Title name
	u8 desc[64];		// Title description
} WIBN;

void yabdm_loop();

#endif /* __YABDM_H__ */
