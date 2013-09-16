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
	WPAD_Init();
	WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);
	
	printheadline();
	
	__debug = false;
	for (i = 1; i < argc; i++)
	{
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
				
				while(true)
				{
					if (DetectInput(DI_BUTTONS_DOWN) != 0)
					{
						resetscreen();
						printheadline();
						break;
					}
				}
				
				break;
			}
		}
	}
	
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
	yabdm_loop();
	
	/* Unmount storage devices, including NAND FS */
	Unmount_Devices();
	
	Reboot();
	
	return 0;
}
