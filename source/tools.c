#include <gccore.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <fat.h>
#include <sdcard/wiisd_io.h>
#include <ogc/usbstorage.h>

#include "tools.h"
#include "net.h"
#include "mload/usb2storage.h"
#include "mload/mload_init.h"

extern DISC_INTERFACE __io_usbstorage;

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;
static FILE *debug_file = NULL;

static vu32 *_wiilight_reg = (u32*)0xCD0000C0;

const char *languages[10] = { "Japanese", "English", "German", "French", "Spanish", "Italian", "Dutch", "Simp. Chinese", "Trad. Chinese", "Korean" };

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

bool is_empty(void *buf, u32 size)
{
    u8 *zero = calloc(size, 1);
	bool i = (memcmp(zero, buf, size) == 0);
	free(zero);
    return i;
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

void waitforbuttonpress()
{
	printf("\n\nPress any button to go back to the menu.");
	fflush(stdout);
	
	while(true)
	{
		if (DetectInput(DI_BUTTONS_DOWN) != 0) break;
	}
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
	printf("\nHacksDen.com, The Hacking Resource Community (2013-2015).\n\n");
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

bool PriiloaderCheck(u64 id)
{
	if (TITLE_UPPER(id) == 1 && TITLE_LOWER(id) == 2)
	{
		char pl_tmd[ISFS_MAXPATH];
		snprintf(pl_tmd, MAX_CHARACTERS(pl_tmd), "/title/00000001/00000002/content/title_or.tmd");
		s32 cfd = ISFS_Open(pl_tmd, ISFS_OPEN_READ);
		if (cfd >= 0)
		{
			ISFS_Close(cfd);
			printf("Priiloader detected in System Menu!\n");
			logfile("Priiloader detected in System Menu!\r\n");
			return true;
		}
	}
	
	return false;
}

bool IsPriiloaderCnt(u16 cid)
{
	char priiloader_cnt[ISFS_MAXPATH];
	snprintf(priiloader_cnt, MAX_CHARACTERS(priiloader_cnt), "/title/00000001/00000002/content/%08x.app", ((1 << 28) | cid));
	s32 cfd = ISFS_Open(priiloader_cnt, ISFS_OPEN_READ);
	if (cfd >= 0)
	{
		ISFS_Close(cfd);
		printf("Priiloader content detected!\n");
		logfile("Priiloader content detected! Original System Menu content file: %08x.app.\r\n", ((1 << 28) | cid));
		return true;
	}
	
	return false;
}

void Close_SD()
{
	fatUnmount("sd");
	__io_wiisd.shutdown();
}

void Init_SD()
{
	//Close_SD();
	SDmnt = fatMountSimple("sd", &__io_wiisd);
	printf("\n\t- SD Card: %s.", (SDmnt ? "OK" : "FAILED"));
}

void Close_USB()
{
	fatUnmount("usb");
	
	if (isUSB2)
	{
		__io_usbstorage2.shutdown();
	} else {
		__io_usbstorage.shutdown();
	}
}

void Init_USB()
{
	//Close_USB();
	
	printf("\n");
	if (AHBPROT_DISABLED && !USB_PORT_CONNECTED)
	{
		USBmnt = false;
	} else {
		bool started = false;
		isUSB2 = (IOS_GetVersion() >= 200);
		
		time_t tStart = time(0);
		while ((time(0) - tStart) < 10) // 10 seconds timeout
		{
			Con_ClearLine();
			printf("\t- USB drive: %.f...", difftime(time(0), tStart));
			
			if (isUSB2)
			{
				started = (__io_usbstorage2.startup() && __io_usbstorage2.isInserted());
			} else {
				started = (__io_usbstorage.startup() && __io_usbstorage.isInserted());
			}
			
			if (started) break;
			
			usleep(50000);
		}
		
		USBmnt = (started && fatMountSimple("usb", (isUSB2 ? &__io_usbstorage2 : &__io_usbstorage)));
		Con_ClearLine();
	}
	
	printf("\t- USB drive: %s.\n\n", (USBmnt ? "OK" : "FAILED"));
}

void Unmount_Devices()
{
	if (debug_file) fclose(debug_file);
	if (SDmnt) Close_SD();
	if (USBmnt) Close_USB();
}

int Mount_Devices()
{
	printf("\n\nMounting available storage devices...\n");
	
	Init_SD();
	Init_USB();
	
	if (!SDmnt && !USBmnt)
	{
		printf("No device detected...");
		return -2;
	} else
	if ((SDmnt && !USBmnt) || (!SDmnt && USBmnt))
	{
		isSD = (SDmnt && !USBmnt);
		printf("The %s will be used as the storage device.", (isSD ? "SD card" : "USB drive"));
		sleep(2);
	} else {
		u32 pressed;
		printf("Press A to use the SD Card.\n");
		printf("Press B to use the USB device.\n");
		
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
	
	return 0;
}

void KeepAccessRightsAndReload(int ios, bool verbose)
{
	s32 ret;
	
	if (AHBPROT_DISABLED)
	{
		/* There should be nothing to worry about if this fails, as long as the new IOS is patched */
		if (verbose) printf("\t- Patching IOS%d to keep hardware access rights... ", IOS_GetVersion());
		ret = IosPatch_AHBPROT(false);
		if (verbose) printf("%s.\n", (ret < 0 ? "FAILED" : "OK"));
	}
	
	if (verbose) printf("\t- Reloading to IOS%d... ", ios);
	WUPC_Shutdown();
	WPAD_Shutdown();
	IOS_ReloadIOS(ios);
	//sleep(2);
	PAD_Init();
	WUPC_Init();
	WPAD_Init();
	WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);
	if (verbose) printf("done.");
	
	if (AHBPROT_DISABLED)
	{
		if (verbose) printf("\n\t- Applying runtime patches to IOS%d... ", IOS_GetVersion());
		ret = IosPatch_RUNTIME(true, false, true, false);
		if (verbose) printf("%s.\n", (ret < 0 ? "FAILED" : "OK"));
	}
	
	if (IsHermesIOS(ios))
	{
		mload_Init();
		if (verbose) printf("\n\t- Hermes cIOS detected! ehcmodule loaded through mload.");
	}
}

int Device_Menu(bool swap)
{
	u32 pressed;
	int i, selection = 0;
	char *dev_opt[2] = { "SD Card", "USB Storage" };
	
	while(true)
	{
		resetscreen();
		printheadline();
		
		printf("Current device: %s.\n\n", DEVICE(1));
		printf("Select the new output device. ");
		printf("%s.\n\n", (swap ? "Press B to swap/remount the storage devices" : "Device swapping is not allowed"));
		
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
			/* Do not exit this screen if the user attempts to select an unavailable storage device */
			if ((selection == 0 && SDmnt) || (selection == 1 && USBmnt))
			{
				/* Detect if the selected device is being already used */
				if ((selection == 0 && !isSD) || (selection == 1 && isSD))
				{
					/* Do the magic */
					isSD ^= 1;
					
					if (debug_file)
					{
						fclose(debug_file);
						logfile_header();
						logfile("Device changed from %s to %s.\r\n\r\n", (selection == 0 ? "USB" : "SD"), DEVICE(1));
					}
				}
				
				return 0;
			}
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
	printf("Otherwise, you can just remount the devices already connected.");
	
	while(true)
	{
		pressed = DetectInput(DI_BUTTONS_DOWN);
		if (pressed == WPAD_BUTTON_A) break;
	}
	
	/* If the currently running IOS is a Waninkoko/d2x cIOS, we have to reload it before we can retry the USB ports */
	int ios = IOS_GetVersion();
	if (ios >= 200 && !IsHermesIOS(ios))
	{
		/* Unmount NAND */
		ISFS_Deinitialize();
		
		/* Do our thing */
		KeepAccessRightsAndReload(ios, false);
		
		/* Remount NAND */
		ISFS_Initialize();
	}
	
	int ret = Mount_Devices();
	if (ret < 0) return ret;
	
	logfile_header();
	return 0;
}

s32 __u8Cmp(const void *a, const void *b)
{
	return *(u8 *)a-*(u8 *)b;
}

u8 *get_ioslist(u32 *cnt)
{
	u64 *buf = 0;
	s32 i, k = 0, res;
	u32 tcnt = 0, icnt = 0;
	u8 *ioses = NULL;
	
	bool skip_title;
	
	/* Get stored IOS versions */
	res = ES_GetNumTitles(&tcnt);
	if (res < 0)
	{
		printf("\t- ES_GetNumTitles: Error! (result = %d).\n", res);
		return 0;
	}
	
	buf = memalign(32, sizeof(u64) * tcnt);
	if (!buf) 
	{
		printf("\t- Error allocating titlelist memory buffer!\n");
		return 0;
	}
	
	res = ES_GetTitles(buf, tcnt);
	if (res < 0)
	{
		printf("\t- ES_GetTitles: Error! (result = %d).\n", res);
		free(buf);
		return 0;
	}
	
	for (i = 0; i < tcnt; i++)
	{
		/* Skip BC, MIOS, System Menu, BootMii IOS, BC-NAND, BC-WFS and stub IOSses */
		if ((TITLE_UPPER(buf[i - k]) == 1) && (TITLE_LOWER(buf[i - k]) > 2) && (TITLE_LOWER(buf[i - k]) < 0xFE))
		{
			u32 tmdSize = 0;
			tmd *iosTMD = NULL;
			signed_blob *iosTMDBuffer = NULL;
			
			/* Get stored TMD size */
			res = ES_GetStoredTMDSize(buf[i - k], &tmdSize);
			if (res < 0)
			{
				printf("\t- ES_GetStoredTMDSize: Error! (result = %d / IOS%d).\n", res, ((u8)buf[i - k]));
				break;
			}
			
			iosTMDBuffer = (signed_blob*)memalign(32, (tmdSize+31)&(~31));
			if (!iosTMDBuffer)
			{
				res = -1;
				printf("\t- Error allocating IOS%d TMD buffer (size = %d bytes).\n", ((u8)buf[i - k]), tmdSize);
				break;
			}
			
			memset(iosTMDBuffer, 0, tmdSize);
			
			/* Get stored TMD */
			res = ES_GetStoredTMD(buf[i - k], iosTMDBuffer, tmdSize);
			if (res < 0)
			{
				printf("\t- ES_GetStoredTMD: Error! (result = %d / IOS%d).\n", res, ((u8)buf[i - k]));
				free(iosTMDBuffer);
				break;
			}
			
			iosTMD = (tmd*)SIGNATURE_PAYLOAD(iosTMDBuffer);
			
			/* Calculate title size */
			int j;
			u32 titleSize = 0;
			for (j = 0; j < iosTMD->num_contents; j++)
			{
				tmd_content *content = &iosTMD->contents[j];
				
				/* Add content size */
				titleSize += content->size;
			}
			
			/* Check if this IOS is a stub */
			skip_title = (titleSize < 0x100000);
			
			free(iosTMDBuffer);
		} else {
			skip_title = true;
		}
		
		if (!skip_title)
		{
			icnt++;
		} else {
			/* Move around memory blocks */
			if ((tcnt - 1) > i)
			{
				memmove(&(buf[i - k]), &(buf[i - k + 1]), (sizeof(u64) * (tcnt - i - 1)));
				k++;
			}
		}
	}
	
	if (res < 0)
	{
		free(buf);
		return 0;
	}
	
	if (realloc(buf, sizeof(u64) * icnt) == NULL)
	{
		printf("\t- Error reallocating titlelist memory block!\n");
		free(buf);
		return 0;
	}
	
	ioses = (u8 *)malloc(sizeof(u8) * icnt);
	if (!ioses)
	{
		printf("\t- Error allocating IOS memory buffer!\n");
		free(buf);
		return 0;
	}
	
	for (i = 0; i < icnt; i++) ioses[i] = (u8)buf[i];
	
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
		
		if (list[i] == IOS_GetVersion()) selection = i;
	}
	
	resetscreen();
	printheadline();
	
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
		
		if (pressed == WPAD_BUTTON_A)
		{
			selection = list[selection];
			break;
		}
		
		if (pressed == WPAD_BUTTON_B)
		{
			selection = 0;
			break;
		}
		
		if (pressed == WPAD_BUTTON_HOME)
		{
			selection = -2;
			break;
		}
	}
	
	free(list);
	return selection;
}

int Settings_Menu()
{
	u32 pressed;
	int i, selection = 0, ret = 0;
	char *menu_opt[3] = { "Device menu", "Update application", "Reload to another IOS (device remount required)" };
	
	while(true)
	{
		resetscreen();
		printheadline();
		
		printf("Select an option. Press B to go back to the menu.\n\n");
		
		for (i = 0; i <= 2; i++)
		{
			printf("%s %s\n", ((selection == i) ? ARROW : "  "), menu_opt[i]);
		}
		
		pressed = DetectInput(DI_BUTTONS_DOWN);
		
		if (pressed == WPAD_BUTTON_UP)
		{
			if (selection > 0) selection--;
		}
		
		if (pressed == WPAD_BUTTON_DOWN)
		{
			if (selection < 2) selection++;
		}
		
		if (pressed == WPAD_BUTTON_A)
		{
			switch (selection)
			{
				case 0:
					/* Device menu */
					ret = Device_Menu(true);
					break;
				case 1:
					/* Update application */
					UpdateYABDM(launch_path);
					break;
				case 2:
					/* IOS reload */
					ret = ios_selectionmenu(249);
					if (ret > 0)
					{
						if (ret != IOS_GetVersion())
						{
							/* Unmount devices */
							ISFS_Deinitialize();
							Unmount_Devices();
							
							KeepAccessRightsAndReload(ret, true);
							
							/* Remount devices */
							ISFS_Initialize();
							ret = Mount_Devices();
							if (ret != -2) logfile_header();
						} else {
							printf("\t- IOS reload aborted (IOS%d is already loaded).", ret);
							waitforbuttonpress();
						}
					} else
					if (ret == 0)
					{
						printf("\t- Proceeding without IOS reload...");
						waitforbuttonpress();
					}
					
					break;
				default:
					break;
			}
			
			break;
		}
		
		if (pressed == WPAD_BUTTON_B) break;
	}
	
	return ret;
}

int ahbprot_menu()
{
	int ret;
	u32 pressed;

	/* HW_AHBPROT check */
	if (AHBPROT_DISABLED)
	{
		printf("Hardware protection is disabled!\n");
		printf("Current IOS: %u.\n\n", IOS_GetVersion());
		
		printf("Press A button to use full hardware access.\n");
		printf("Press B button to reload to another IOS.\n");
		printf("Press HOME or Start to exit.\n\n");
		
		for (;;)
		{
			pressed = DetectInput(DI_BUTTONS_DOWN);
			
			/* A button */
			if (pressed == WPAD_BUTTON_A)
			{
				printf("Initializing IOS patches... ");
				ret = IosPatch_RUNTIME(true, false, true, false);
				if (ret < 0)
				{
					/* This is a very, very weird error */
					printf("ERROR!\n\n");
					printf("\tUnable to load the initial patches. Maybe the loaded IOS isn't\n");
					printf("\tvulnerable for an unknown reason.\n");
					sleep(4);
					printf("\tThis error is very uncommon. I already checked if the hardware\n");
					printf("\tprotection was disabled. You should report this to me as soon as\n");
					printf("\tyou can.\n");
					sleep(4);
					printf("\tI'll let you reload to another IOS instead of kicking you out\n");
					printf("\tto the loader...");
					sleep(4);
				} else {
					printf("OK!");
				}
				
				break;
			}
			
			/* B button */
			if (pressed == WPAD_BUTTON_B)
			{
				ret = -1;
				break;
			}
			
			/* HOME/Start button */
			if (pressed == WPAD_BUTTON_HOME) return -1;
		}
	} else {
		ret = -1;
	}
	
	if (ret < 0)
	{
		ret = ios_selectionmenu(249);
		if (ret > 0)
		{
			if (ret != IOS_GetVersion())
			{
				KeepAccessRightsAndReload(ret, true);
			} else {
				printf("\t- IOS reload aborted (IOS%d is already loaded).", ret);
			}
		} else
		if (ret == 0)
		{
			printf("\t- Proceeding without IOS reload...");
		} else {
			return ret;
		}
	}
	
	return 0;
}

void logfile(const char *format, ...)
{
	if (__debug)
	{
		if (!debug_file)
		{
			char logpath[20];
			snprintf(logpath, MAX_CHARACTERS(logpath), "%s:/YABDM.log", DEVICE(0));
			debug_file = fopen(logpath, "a");
			if (!debug_file) return;
		}
		
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
	logfile("\r\n\r\n*---------------------------------------------------------------------------------------------------------------------------*\r\n");
	logfile("\r\n\r\nYet Another BlueDump MOD v%s - Logfile.\r\n", VERSION);
	logfile("SDmnt(%d), USBmnt(%d), isUSB2(%d), isSD(%d), vwii(%d), __wiilight(%d).\r\n", SDmnt, USBmnt, isUSB2, isSD, vwii, __wiilight);
	logfile("Using IOS%u v%u.\r\n", IOS_GetVersion(), IOS_GetRevision());
	logfile("Console language: %d (%s).\r\n\r\n", lang, languages[lang]);
}

void hexdump_log(void *d, int len)
{
	if (__debug)
	{
		int i, f, off;
		u8 *data = (u8*)d;
		for (off = 0; off < len; off += 16)
		{
			logfile("%08x:  ", 16 * (off / 16));
			for (f = 0; f < 16; f += 4)
			{
				for (i = 0; i < 4; i++)
				{
					if ((i + off) >= len)
					{
						logfile(" ");
					} else {
						logfile("%02x", data[off + f + i]);
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
		for (i = 0; i < len; i++) logfile("%02x ", data[i]);
	}
}
