#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gccore.h>
#include <ogcsys.h>

#include "tools.h"

extern void __exception_setreload(int);

void bluedump_loop();

int main(int argc, char* argv[])
{
	__exception_setreload(10);
	
	int ret;
	u32 pressed;
	u32 pressedGC;
	
	Init_Console();
	printf("\x1b[%u;%um", 37, false);
	
	PAD_Init();
	WPAD_Init();
	WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);
	
	printheadline();
	
	ret = ahbprot_menu();
	if (ret < 0)
	{
		ret = ios_selectionmenu(236);
		if (ret != 0)
		{
			printf("\n\t- Reloading to IOS%d... ", ret);
			WPAD_Shutdown();
			IOS_ReloadIOS(ret);
			sleep(2);
			PAD_Init();
			WPAD_Init();
			WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);
			printf("done.\n\n");
		} else {
			printf("\n\t- Proceeding without IOS reload...\n\n");
		}
	}
	
	/* Initialize NAND FS */
	ISFS_Initialize();
	
	/* Mount available storage devices */
	printf("Mounting available storage devices...\n");
	Mount_Devices();
	
	/* Main app loop */
	bluedump_loop();
	
	/* Unmount storage devices, including NAND FS */
	Unmount_Devices();
	
	Reboot();
	
	return 0;
}
