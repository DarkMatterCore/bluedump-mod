#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <sys/unistd.h>
#include <wiiuse/wpad.h>
#include <runtimeiospatch.h>
#include <malloc.h>

#define VERSION "1.0"

// Values for DetectInput
#define DI_BUTTONS_DOWN		0
#define DI_BUTTONS_HELD		1

#define resetscreen() printf("\x1b[2J")
#define IsWiiU() ((*(vu32*)(0xCD8005A0) >> 16 ) == 0xCAFE)

typedef struct map_entry
{
	char filename[8];
	u8 sha1[20];
} __attribute__((packed)) map_entry_t;

map_entry_t *cm;
size_t content_map_size;
size_t content_map_items;

bool SDmnt, USBmnt, isSD, __debug, vwii;

u32 DetectInput(u8 DownOrHeld);
void Init_Console();
void printheadline();
void set_highlight(bool highlight);
void Con_ClearLine();
void Unmount_Devices();
void goodbye();
void Mount_Devices();
int ahbprot_menu();
int ios_selectionmenu(int default_ios);
void reset_log();
void logfile(const char *format, ...);
void hexdump_log(void *d, int len);
void hex_key_dump(void *d, int len);

#endif /* __TOOLS_H__ */
