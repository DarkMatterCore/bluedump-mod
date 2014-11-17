#include <gccore.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <fat.h>
#include <sdcard/wiisd_io.h>
#include <ogc/usbstorage.h>

#include "tools.h"

extern DISC_INTERFACE __io_usbstorage;

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;
static FILE *debug_file = NULL;

char *languages[10] = { "Japanese", "English", "German", "French", "Spanish", "Italian", "Dutch", "Simp. Chinese", "Trad. Chinese", "Korean" };

static vu32 *_wiilight_reg = (u32*)0xCD0000C0;

void WiiDiscLight(bool turn_on)
{
	if (__wiilight)
	{
		*_wiilight_reg = ((*_wiilight_reg & ~0x20) | (turn_on ? 0x20 : 0x00));
	}
}

u32 __fread(void *out, u32 size, u32 cnt, FILE *src)
{
	WiiDiscLight(true);
	u32 ret = fread(out, size, cnt, src);
	WiiDiscLight(false);
	
	return ret;
}

u32 __fwrite(const void *src, u32 size, u32 cnt, FILE *out)
{
	WiiDiscLight(true);
	u32 ret = fwrite(src, size, cnt, out);
	WiiDiscLight(false);
	
	return ret;
}

void Reboot()
{
	if (*(u32*)0x80001800) exit(0);
	SYS_ResetSystem(SYS_RETURNTOMENU, 0, 0);
}

/* Big thanks to JoostinOnline for the new controller code */
u32 DetectInput(u8 DownOrHeld)
{
	u32 pressed = 0;
	u32 gcpressed = 0;
	VIDEO_WaitVSync();
	
	// WiiMote, Classic Controller and Wii U Pro Controller take precedence over the GCN Controller to save time
	if (WUPC_UpdateButtonStats() > WPAD_ERR_NONE)
	{
		if (DownOrHeld == DI_BUTTONS_DOWN)
		{
			pressed = WUPC_ButtonsDown(0) | WUPC_ButtonsDown(1) | WUPC_ButtonsDown(2) | WUPC_ButtonsDown(3); // Store pressed buttons
		} else {
			pressed = WUPC_ButtonsHeld(0) | WUPC_ButtonsHeld(1) | WUPC_ButtonsHeld(2) | WUPC_ButtonsHeld(3); // Store held buttons
		}
	} else
	if (WPAD_ScanPads() > WPAD_ERR_NONE)
	{
		if (DownOrHeld == DI_BUTTONS_DOWN)
		{
			pressed = WPAD_ButtonsDown(0) | WPAD_ButtonsDown(1) | WPAD_ButtonsDown(2) | WPAD_ButtonsDown(3); // Store pressed buttons
		} else {
			pressed = WPAD_ButtonsHeld(0) | WPAD_ButtonsHeld(1) | WPAD_ButtonsHeld(2) | WPAD_ButtonsHeld(3); // Store held buttons
		} 
	}
		
	// Convert to WiiMote values
	if (pressed & WPAD_CLASSIC_BUTTON_ZR) pressed |= WPAD_BUTTON_PLUS;
	if (pressed & WPAD_CLASSIC_BUTTON_ZL) pressed |= WPAD_BUTTON_MINUS;
	
	if (pressed & WPAD_CLASSIC_BUTTON_PLUS) pressed |= WPAD_BUTTON_PLUS;
	if (pressed & WPAD_CLASSIC_BUTTON_MINUS) pressed |= WPAD_BUTTON_MINUS;
	
	if (pressed & WPAD_CLASSIC_BUTTON_A) pressed |= WPAD_BUTTON_A;
	if (pressed & WPAD_CLASSIC_BUTTON_B) pressed |= WPAD_BUTTON_B;
	if (pressed & WPAD_CLASSIC_BUTTON_X) pressed |= WPAD_BUTTON_2;
	if (pressed & WPAD_CLASSIC_BUTTON_Y) pressed |= WPAD_BUTTON_1;
	if (pressed & WPAD_CLASSIC_BUTTON_HOME) pressed |= WPAD_BUTTON_HOME;
	
	if (pressed & WPAD_CLASSIC_BUTTON_UP) pressed |= WPAD_BUTTON_UP;
	if (pressed & WPAD_CLASSIC_BUTTON_DOWN) pressed |= WPAD_BUTTON_DOWN;
	if (pressed & WPAD_CLASSIC_BUTTON_LEFT) pressed |= WPAD_BUTTON_LEFT;
	if (pressed & WPAD_CLASSIC_BUTTON_RIGHT) pressed |= WPAD_BUTTON_RIGHT;
	
	// Return WiiMote / Classic Controller / Wii U Pro Controller values
	if (pressed) return pressed;
	
	// No buttons on the WiiMote or Classic Controller were pressed
	if (PAD_ScanPads() > PAD_ERR_NONE)
	{
		if (DownOrHeld == DI_BUTTONS_DOWN)
		{
			gcpressed = PAD_ButtonsDown(0) | PAD_ButtonsDown(1) | PAD_ButtonsDown(2) | PAD_ButtonsDown(3); // Store pressed buttons
		} else {
			gcpressed = PAD_ButtonsHeld(0) | PAD_ButtonsHeld(1) | PAD_ButtonsHeld(2) | PAD_ButtonsHeld(3); // Store held buttons
		}
		
		// Convert to WiiMote values
		if (gcpressed & PAD_TRIGGER_R) pressed |= WPAD_BUTTON_PLUS;
		if (gcpressed & PAD_TRIGGER_L) pressed |= WPAD_BUTTON_MINUS;
		if (gcpressed & PAD_BUTTON_A) pressed |= WPAD_BUTTON_A;
		if (gcpressed & PAD_BUTTON_B) pressed |= WPAD_BUTTON_B;
		if (gcpressed & PAD_BUTTON_X) pressed |= WPAD_BUTTON_2;
		if (gcpressed & PAD_BUTTON_Y) pressed |= WPAD_BUTTON_1;
		if (gcpressed & PAD_BUTTON_MENU) pressed |= WPAD_BUTTON_HOME;
		if (gcpressed & PAD_BUTTON_UP) pressed |= WPAD_BUTTON_UP;
		if (gcpressed & PAD_BUTTON_DOWN) pressed |= WPAD_BUTTON_DOWN;
		if (gcpressed & PAD_BUTTON_LEFT) pressed |= WPAD_BUTTON_LEFT;
		if (gcpressed & PAD_BUTTON_RIGHT) pressed |= WPAD_BUTTON_RIGHT;
	}
	
	return pressed;
}

void Init_Console()
{
	// Initialise the video system
	VIDEO_Init();
	
	// Obtain the preferred video mode from the system
	// This will correspond to the settings in the Wii menu
	rmode = VIDEO_GetPreferredMode(NULL);

	// Allocate memory for the display in the uncached region
	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	
	// Set up the video registers with the chosen mode
	VIDEO_Configure(rmode);
	
	// Tell the video hardware where our display memory is
	VIDEO_SetNextFramebuffer(xfb);
	
	// Make the display visible
	VIDEO_SetBlack(FALSE);

	// Flush the video register changes to the hardware
	VIDEO_Flush();

	// Wait for Video setup to complete
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();

	// Set console parameters
    int x = 24, y = 32, w, h;
    w = rmode->fbWidth - (32);
    h = rmode->xfbHeight - (48);

    // Initialize the console - CON_InitEx works after VIDEO_ calls
	CON_InitEx(rmode, x, y, w, h);

	// Clear the garbage around the edges of the console
    VIDEO_ClearFrameBuffer(rmode, xfb, COLOR_BLACK);
}

void printheadline()
{
	int rows, cols;
	CON_GetMetrics(&cols, &rows);
	
	printf("Yet Another BlueDump MOD v%s.", VERSION);
	
	char buf[64];
	sprintf(buf, "IOS%u (v%u)", IOS_GetVersion(), IOS_GetRevision());
	printf("\x1b[%d;%dH", 0, cols-strlen(buf)-1);
	printf(buf);
	
	printf("\nOriginal code by nicksasa and WiiPower.");
	printf("\nUpdated by DarkMatterCore. Additional code by JoostinOnline.");
	printf("\nHacksDen.com, The Hacking Resource Community (2013-2014).\n\n");
}

void set_highlight(bool highlight)
{
	if (highlight)
	{
		printf("\x1b[%u;%um", 47, false);
		printf("\x1b[%u;%um", 30, false);
	} else {
		printf("\x1b[%u;%um", 37, false);
		printf("\x1b[%u;%um", 40, false);
	}
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
	for (cnt = 1; cnt < cols; cnt++)
	{
		printf(" ");
		fflush(stdout);
	}

	printf("\r");
	fflush(stdout);
}

s32 Init_SD()
{
	fatUnmount("sd");
	
	__io_wiisd.shutdown();
	
	if (!fatMountSimple("sd", &__io_wiisd)) return -1;
	
	return 0;
}

void Close_SD()
{
	fatUnmount("sd");
	__io_wiisd.shutdown();
}

s32 Init_USB()
{
	fatUnmount("usb");
	
	bool isMounted = fatMountSimple("usb", &__io_usbstorage);
	
	if (!isMounted)
	{
		bool isInserted = __io_usbstorage.isInserted();
		
		if (isInserted)
		{
			int retry = 10;
			
			while (retry > 0)
			{ 
				isMounted = fatMountSimple("usb", &__io_usbstorage);
				if (isMounted) return 0;
				usleep(1000000);
				retry--;
			}
		}
		
		return -1;
	}
	
	return 0;
}

void Close_USB()
{
	fatUnmount("usb");
	__io_usbstorage.shutdown();
}

void Unmount_Devices()
{
	if (debug_file) fclose(debug_file);
	
	if (SDmnt) Close_SD();
	
	if (USBmnt) Close_USB();
}

void goodbye()
{
	fflush(stdout);
	if (cm) free(cm);
	ISFS_Deinitialize();
	Unmount_Devices();
	Reboot();
}

void Mount_Devices()
{
	int ret;
	u32 pressed;
	
	printf("Mounting available storage devices...\n");
	
	printf("\n\t- SD Card: ");
	ret = Init_SD();
	if (ret < 0)
	{
		printf("FAILED.\n");
		SDmnt = false;
	} else {
		printf("OK.\n");
		SDmnt = true;
	}
	
	printf("\n\t- USB drive: ");
	ret = Init_USB();
	if (ret < 0)
	{
		printf("FAILED.\n");
		USBmnt = false;
	} else {
		printf("OK.\n");
		USBmnt = true;
	}
	
	if (SDmnt && !USBmnt)
	{
		isSD = true;
		printf("\nThe SD Card will be used as the storage device.");
		sleep(2);
	} else
	if (!SDmnt && USBmnt)
	{
		isSD = false;
		printf("\nThe USB drive will be used as the storage device.");
		sleep(2);
	} else
	if (!SDmnt && !USBmnt)
	{
		printf("\nNo device detected. Good bye...");
		goodbye();
	} else {
		printf("\nPress A to use the SD Card.\n");
		printf("Press B to use the USB device.");
		
		while(true)
		{
			pressed = DetectInput(DI_BUTTONS_DOWN);
			
			if (pressed == WPAD_BUTTON_A)
			{
				isSD = true;
				break;
			}
			
			if (pressed == WPAD_BUTTON_B)
			{
				isSD = false;
				break;
			}
		}
	}
}

void Device_Menu(bool swap)
{
	u32 pressed;
	int i, selection = 0;
	char *dev_opt[2] = { "SD Card", "USB Storage" };
	
	while(true)
	{
		resetscreen();
		printheadline();
		
		printf("Current device: %s.\n\n", DEVICE(1));
		printf("Select the new output device.");
		if (swap)
		{
			printf(" Press B to swap/remount the storage devices.\n\n");
		} else {
			printf(" Device swapping is not allowed.\n\n");
		}
		
		for (i = 0; i <= 1; i++)
		{
			printf("%s %s %s\n", ((selection == i) ? ARROW : "  "), dev_opt[i], (((i == 0 && SDmnt) || (i == 1 && USBmnt)) ? "(available)" : "(not available)"));
		}
		
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		if (pressed == WPAD_BUTTON_UP)
		{
			if (selection > 0) selection--;
		}
		
		if (pressed == WPAD_BUTTON_DOWN)
		{
			if (selection < 1) selection++;
		}
		
		if (pressed == WPAD_BUTTON_A)
		{
			if ((selection == 0 && SDmnt && !isSD) || (selection == 1 && USBmnt && isSD))
			{
				isSD ^= 1;
				if (debug_file)
				{
					fclose(debug_file);
					
					logfile_header();
				}
			}
			
			return;
		}
		
		if (pressed == WPAD_BUTTON_B)
		{
			if (swap) break;
		}
	}
	
	resetscreen();
	printheadline();
	
	Unmount_Devices();
	
	printf("Swap the current storage devices if you want to use different ones.\n");
	printf("Press A when you're done to mount them.\n");
	printf("Otherwise, you can just remount the devices already connected.\n\n");
	
	while(true)
	{
		pressed = DetectInput(DI_BUTTONS_DOWN);
		if (pressed == WPAD_BUTTON_A) break;
	}
	
	Mount_Devices();
	
	logfile_header();
}

int ahbprot_menu()
{
	s32 ret;
	u32 pressed;

	/* HW_AHBPROT check */
	if (AHBPROT_DISABLED)
	{
		printf("Hardware protection is disabled!\n");
		printf("Current IOS: %u.\n\n", IOS_GetVersion());
		
		printf("Press A button to use full hardware access.\n");
		printf("Press B button to reload to another IOS.\n");
		printf("Press HOME or Start to exit.\n\n");
		
		for(;;)
		{
			pressed = DetectInput(DI_BUTTONS_DOWN);
			
			/* A button */
			if (pressed == WPAD_BUTTON_A) break;
			
			/* B button */
			if (pressed == WPAD_BUTTON_B)
			{
				resetscreen();
				printheadline();
				return -1;
			}
			
			/* HOME/Start button */
			if (pressed == WPAD_BUTTON_HOME)
			{
				printf("Exiting...");
				goodbye();
			}
		}
		
		printf("Initializing IOS patches... ");
		ret = IosPatch_RUNTIME(true, false, true, false);
		if (ret < 0)
		{
			/* This is a very, very weird error */
			
			printf("ERROR!\n\n");
			printf("\tUnable to load the initial patches. Maybe the loaded IOS isn't\n");
			printf("\tvulnerable for an unknown reason.\n");
			sleep(4);
			printf("\tThis error is very uncommon. I already checked if the HW_AHBPROT\n");
			printf("\tprotection was disabled. You should report this to me as soon as\n");
			printf("\tyou can.\n");
			sleep(4);
			printf("\tI'll let you reload to another IOS instead of kicking you out\n");
			printf("\tto the loader...");
			sleep(4);
			
			resetscreen();
			printheadline();
			
			return -1;
		}
		
		printf("OK!\n\n");
	} else {
		return -1;
	}
	
	return 0;
}

s32 __u8Cmp(const void *a, const void *b)
{
	return *(u8 *)a-*(u8 *)b;
}

u8 *get_ioslist(u32 *cnt)
{
	u64 *buf = 0;
	s32 i, res;
	u32 tcnt = 0, icnt;
	u8 *ioses = NULL;
	
	// Get stored IOS versions.
	res = ES_GetNumTitles(&tcnt);
	if (res < 0)
	{
		printf("\t- ES_GetNumTitles: Error! (result = %d).\n", res);
		return 0;
	}
	
	buf = memalign(32, sizeof(u64) * tcnt);
	if (!buf) 
	{
		printf("\t- Error allocating memory buffer!\n");
		return 0;
	}
	
	res = ES_GetTitles(buf, tcnt);
	if (res < 0)
	{
		printf("\t- ES_GetTitles: Error! (result = %d).\n", res);
		free(buf);
		return 0;
	}

	icnt = 0;
	for(i = 0; i < tcnt; i++)
	{
		if(*((u32 *)(&(buf[i]))) == 1 && (u32)buf[i] > 2 && (u32)buf[i] < 0x100)
		{
			icnt++;
			ioses = (u8 *)realloc(ioses, sizeof(u8) * icnt);
			ioses[icnt - 1] = (u8)buf[i];
		}
	}

	ioses = (u8 *)malloc(sizeof(u8) * icnt);
	if (!ioses)
	{
		printf("\t- Error allocating IOS memory buffer!\n");
		free(buf);
		return 0;
	}
	
	icnt = 0;
	
	for (i = 0; i < tcnt; i++)
	{
		if(*((u32 *)(&(buf[i]))) == 1 && (u32)buf[i] > 2 && (u32)buf[i] < 0x100)
		{
			icnt++;
			ioses[icnt - 1] = (u8)buf[i];
		}
	}
	
	free(buf);
	qsort(ioses, icnt, 1, __u8Cmp);

	*cnt = icnt;
	return ioses;
}

int ios_selectionmenu(int default_ios)
{
	u32 pressed;
	int i, selection = 0;
	u32 ioscount;
	
	u8 *list = get_ioslist(&ioscount);
	if (list == 0) return -1;
	
	for (i = 0; i < ioscount; i++)
	{
		/* Default to default_ios if found, else the loaded IOS */
		
		if (list[i] == default_ios)
		{
			selection = i;
			break;
		}
		
		if (list[i] == IOS_GetVersion())
		{
			selection = i;
		}
	}
	
	while (true)
	{
		printf("\x1b[%d;%dH", 5, 0);	// move console cursor to y/x
		printf("Select the IOS version to use:       \b\b\b\b\b\b");
		
		set_highlight(true);
		printf("IOS%u", list[selection]);
		set_highlight(false);
		
		printf("\n\nPress LEFT/RIGHT to change IOS version.");
		printf("\nPress A button to load the selected IOS.");
		printf("\nPress B to continue without IOS Reload.");
		printf("\nPress HOME or Start to exit.\n\n");
		
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		if (pressed == WPAD_BUTTON_LEFT)
		{	
			if (selection > 0)
			{
				selection--;
			} else {
				selection = ioscount - 1;
			}
		}
		
		if (pressed == WPAD_BUTTON_RIGHT)
		{
			if (selection < ioscount -1)
			{
				selection++;
			} else {
				selection = 0;
			}
		}
		
		if (pressed == WPAD_BUTTON_A) break;
		
		if (pressed == WPAD_BUTTON_B) return 0;
		
		if (pressed == WPAD_BUTTON_HOME)
		{
			printf("Exiting...");
			free(list);
			goodbye();
		}
	}
	
	selection = list[selection];
	free(list);
	
	return selection;
}

void logfile(const char *format, ...)
{
	if (__debug)
	{
		if (!debug_file)
		{
			if (isSD)
			{
				debug_file = fopen("sd:/YABDM.log", "a");
			} else {
				debug_file = fopen("usb:/YABDM.log", "a");
			}
		}
		
		if (!debug_file) return;
		
		WiiDiscLight(true);
		
		va_list args;
		va_start(args, format);
		vfprintf(debug_file, format, args);
		fflush(debug_file);
		va_end(args);
		
		WiiDiscLight(false);
	}
}

void logfile_header()
{
	logfile("\r\n*---------------------------------------------------------------------------------------------------------------------------*\r\n");
	logfile("\r\nYet Another BlueDump MOD v%s - Logfile.\r\n", VERSION);
	logfile("SDmnt(%d), USBmnt(%d), isSD(%d), vwii(%d), __wiilight(%d).\r\n", SDmnt, USBmnt, isSD, vwii, __wiilight);
	logfile("Using IOS%u v%u.\r\n", IOS_GetVersion(), IOS_GetRevision());
	logfile("Console language: %d (%s).\r\n\r\n", lang, languages[lang]);
}

void hexdump_log(void *d, int len)
{
	if (__debug)
	{
		int i, f, off;
		u8 *data = (u8*)d;
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
					} else {
						logfile("%02x",data[off+f+i]);
					}  
				}
				logfile(" ");
			}
			logfile("\r\n");
		}
		logfile("\r\n");
	}
}

void hex_key_dump(void *d, int len)
{
	if (__debug)
	{
		int i;
		u8 *data = (u8*)d;
		
		for(i = 0; i < len; i++) logfile("%02x ", data[i]);
	}
}
