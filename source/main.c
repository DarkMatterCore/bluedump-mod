#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gccore.h>
#include <ogcsys.h>

#include "yabdm.h"
#include "tools.h"

// Check if string X is in current argument
#define CHECK_ARG(X) (!strncmp((X), argv[i], sizeof((X))-1))
#define CHECK_ARG_VAL(X) (argv[i] + sizeof((X))-1)

extern void __exception_setreload(int);

int main(int argc, char* argv[])
{
	__exception_setreload(10);
	
	int i, ret;
	
	Init_Console();
	printf("\x1b[%u;%um", 37, false);
	
	PAD_Init();
	WUPC_Init();
	WPAD_Init();
	WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);
	
	printheadline();
	
	vwii = IsWiiU();
	__debug = false;
	__wiilight = false;
	
	/* Also check argv[0], since it appears arguments get initially passed here if Wiiload is launched from a batch script */
	for (i = 0; i < argc; ++i)
	{
		/* Check "debug" argument */
		if (CHECK_ARG("debug="))
		{
			if (atoi(CHECK_ARG_VAL("debug=")) == 1)
			{
				__debug = true;
				
				printf("Debug mode activated!\n\n");
				printf("Overall application performance may be slower than before.\n");
				printf("This is completely normal, and is because debug info will be constantly\n");
				printf("written to the \"YABDM.log\" file in the selected storage device.\n\n");
				printf("Press any button to continue...");
				fflush(stdout);
				
				while(true)
				{
					if (DetectInput(DI_BUTTONS_DOWN) != 0)
					{
						resetscreen();
						printheadline();
						break;
					}
				}
			}
		}
		
		/* Check "wiilight" argument */
		if (CHECK_ARG("wiilight="))
		{
			if (atoi(CHECK_ARG_VAL("wiilight=")) == 1) __wiilight = true;
		}
	}
	
	ret = ahbprot_menu();
	if (ret >= 0)
	{
		/* Initialize NAND FS */
		ISFS_Initialize();
		
		/* Mount available storage devices */
		ret = Mount_Devices();
		if (ret >= 0)
		{
			/* Copy launch path */
			if (argv[0] != NULL) snprintf(launch_path, MAX_CHARACTERS(launch_path), argv[0]);
			
			/* Main app loop */
			yabdm_loop();
		}
	}
	
	/* Unmount storage devices (including NAND FS) and exit */
	fflush(stdout);
	if (cm) free(cm);
	ISFS_Deinitialize();
	Unmount_Devices();
	Reboot();
	
	return 0;
}
