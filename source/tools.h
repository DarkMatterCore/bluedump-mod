#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <sys/unistd.h>
#include <wiiuse/wpad.h>
#include <wupc/wupc.h>
#include <runtimeiospatch.h>
#include <malloc.h>

#define VERSION "1.6"

// Values for DetectInput
#define DI_BUTTONS_DOWN		0
#define DI_BUTTONS_HELD		1

#define resetscreen() printf("\x1b[2J")
#define IsWiiU() ((*(vu32*)(0xCD8005A0) >> 16 ) == 0xCAFE)

#define ARROW " \x10"
#define DEVICE(x) (((x) == 0) ? (isSD ? "sd" : "usb") : (isSD ? "SD" : "USB"))
#define MAX_CHARACTERS(x) ((sizeof((x))) / (sizeof((x)[0]))) // Returns the number of elements in an array

typedef struct map_entry
{
	char filename[8];
	u8 sha1[20];
} __attribute__((packed)) map_entry_t;

map_entry_t *cm;
size_t content_map_size;
size_t content_map_items;

int lang;
bool SDmnt, USBmnt, isSD, __debug, vwii, __wiilight;

u32 __fread(void *out, u32 size, u32 cnt, FILE *src);
u32 __fwrite(const void *src, u32 size, u32 cnt, FILE *out);
u32 DetectInput(u8 DownOrHeld);
void Init_Console();
void printheadline();
void set_highlight(bool highlight);
void Con_ClearLine();
void Unmount_Devices();
void goodbye();
void Mount_Devices();
void Device_Menu(bool swap);
int ahbprot_menu();
int ios_selectionmenu(int default_ios);
void logfile(const char *format, ...);
void logfile_header();
void hexdump_log(void *d, int len);
void hex_key_dump(void *d, int len);

#endif /* __TOOLS_H__ */
