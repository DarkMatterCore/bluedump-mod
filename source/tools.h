#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <sys/unistd.h>
#include <wiiuse/wpad.h>
#include <wupc/wupc.h>
#include <runtimeiospatch.h>
#include <malloc.h>

#define VERSION "1.85"

#define MAXPATHLEN 256

// Values for DetectInput
#define DI_BUTTONS_DOWN		0
#define DI_BUTTONS_HELD		1

#define resetscreen() printf("\x1b[2J")
//#define IsWiiU() ((*(vu32*)(0xCD8005A0) >> 16 ) == 0xCAFE)

#define ARROW " \x10"
#define DEVICE(x) (((x) == 0) ? (isSD ? "sd" : "usb") : (isSD ? "SD" : "USB"))
#define MAX_CHARACTERS(x) ((sizeof((x))) / (sizeof((x)[0]))) // Returns the number of elements in an array

#define TITLE_UPPER(x)		((u32)((x) >> 32))
#define TITLE_LOWER(x)		((u32)(x))
#define TITLE_ID(x,y)		(((u64)(x) << 32) | (y))

#define IsHermesIOS(ios) ((ios) == 202 || (ios) == 222 || (ios) == 223 || (ios) == 224 || (ios) == 225)

#define TITLEID_200			0x0000000100000200ll // IOS512

typedef struct map_entry
{
	char filename[8];
	u8 sha1[20];
} __attribute__((packed)) map_entry_t;

map_entry_t *cm;
size_t content_map_size;
size_t content_map_items;

int lang;
bool SDmnt, USBmnt, isSD, isUSB2, __debug, __wiilight, vwii, netw_init;

char launch_path[MAXPATHLEN];

bool IsWiiU(void);
u32 __fread(void *out, u32 size, u32 cnt, FILE *src);
u32 __fwrite(const void *src, u32 size, u32 cnt, FILE *out);
bool is_empty(void *buf, u32 size);
void Reboot();
u32 DetectInput(u8 DownOrHeld);
void waitforbuttonpress();
void Init_Console();
void printheadline();
void set_highlight(bool highlight);
void Con_ClearLine();
bool PriiloaderCheck(u64 id);
bool IsPriiloaderCnt(u16 cid);
void Unmount_Devices();
int Mount_Devices();
int Device_Menu(bool swap);
s32 Settings_Menu();
s32 ahbprot_menu();
void logfile(const char *format, ...);
void logfile_header();
void hexdump_log(void *d, int len);
void hex_key_dump(void *d, int len);

#endif /* __TOOLS_H__ */
