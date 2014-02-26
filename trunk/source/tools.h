#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <sys/unistd.h>
#include <wiiuse/wpad.h>
#include <malloc.h>
#include <runtimeiospatch.h>

#define VERSION "0.9"

#define resetscreen() printf("\x1b[2J")

bool SDmnt, USBmnt, isSD, __debug, vwii;

void Reboot();
inline bool IsWiiU();
void waitforbuttonpress(u32 *out, u32 *outGC);
void Init_Console();
void printheadline();
void set_highlight(bool highlight);
void Con_ClearLine();
int ahbprot_menu();
int ios_selectionmenu(int default_ios);
void Mount_Devices();
void Unmount_Devices();
void reset_log();
void logfile(const char *format, ...);
void hexdump_log(void *d, int len);
void hex_key_dump(void *d, int len);

#endif /* __TOOLS_H__ */
