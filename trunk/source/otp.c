#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools.h"
#include "otp.h"

#define HW_OTP_COMMAND (*(vu32*)0xcd8001ec)
#define HW_OTP_DATA (*(vu32*)0xcd8001f0)
#define OTP_SIZE 0x80

static u8 otp_ptr[OTP_SIZE];

void OTP_Unmount()
{
	memset(otp_ptr, 0, OTP_SIZE);
}

static bool OTP_Mount()
{
	OTP_Unmount();
	
	u8 addr;
	
	for (addr = 0; addr < 32; addr++)
	{
		HW_OTP_COMMAND = 0x80000000 | addr;
		*(((u32 *)otp_ptr) + addr) = HW_OTP_DATA;
	}
	
	return *otp_ptr;
}

s32 Get_OTP_data()
{
	otp_t *otp_data = memalign(32, sizeof(otp_t));
	
	bool read_otp = OTP_Mount();
	if (!read_otp)
	{
		OTP_Unmount();
		free(otp_data);
		printf("Fatal error: OTP_Mount failed.");
		logfile("Fatal error: OTP_Mount failed.");
		return -1;
	}
	
	memcpy(otp_data, otp_ptr, sizeof(otp_t));
	OTP_Unmount();
	
	/* Copy PRNG Key */
	memcpy(prng_key, otp_data->rng_key, 16);
	logfile("PRNG Key: ");
	hex_key_dump(prng_key, 16);
	logfile("... ");
	
	/* Copy Console ID */
	memcpy(&console_id, otp_data->ng_id, 4);
	logfile("Console ID: %08x... ", console_id);
	
	free(otp_data);
	
	return 0;
}

s32 Get_BootMii_data(u32 cntbin_cid)
{
	if (bootmii_cid == 0)
	{
		bool is_nandbin = false;
		
		char filepath[20] = {0};
		snprintf(filepath, MAX_CHARACTERS(filepath), "%s:/keys.bin", DEVICE(0));
		
		printf("\nReading BootMii data from a different console... ");
		logfile("\r\nReading BootMii data from a different console... ");
		
		FILE *bootmii_file = fopen(filepath, "rb");
		if (!bootmii_file)
		{
			snprintf(filepath, MAX_CHARACTERS(filepath), "%s:/nand.bin", DEVICE(0));
			bootmii_file = fopen(filepath, "rb");
			if (!bootmii_file)
			{
				printf("BootMii data not found!\n");
				logfile("BootMii data not found!\r\n");
				return -1;
			} else {
				is_nandbin = true;
			}
		}
		
		/* keys.bin layout */
		/* Header (0x000): 0x100 bytes */
		/* OTP data (0x100): 0x80 bytes */
		/* Zero padding (0x180): 0x80 bytes */
		/* SEEPROM data (0x200): 0x100 bytes */
		/* Zero padding (0x300): 0x100 bytes */
		
		/* nand.bin layout */
		/* NAND dump + ECC data (0x00000000): 0x21000000 bytes (528 MB) */
		/* Copy of keys.bin (0x21000000): 0x400 bytes */
		/* NAND dumps created by old versions of BootMii do not have a copy of keys.bin */
		
		if (is_nandbin)
		{
			fseek(bootmii_file, 0, SEEK_END);
			if (ftell(bootmii_file) < 0x21000400)
			{
				printf("\nThe available nand.bin file doesn't have a copy of keys.bin!\n");
				logfile("The available nand.bin file doesn't have a copy of keys.bin!\r\n");
				fclose(bootmii_file);
				return -1;
			} else {
				rewind(bootmii_file);
			}
		}
		
		otp_t *otp_data = memalign(32, sizeof(otp_t));
		
		fseek(bootmii_file, (is_nandbin ? 0x21000100 : 0x100), SEEK_SET);
		__fread(otp_data, sizeof(otp_t), 1, bootmii_file);
		fclose(bootmii_file);
		
		/* Copy PRNG Key */
		memcpy(bootmii_prng, otp_data->rng_key, 16);
		logfile("BootMii PRNG Key: ");
		hex_key_dump(bootmii_prng, 16);
		logfile("... ");
		
		/* Copy Console ID */
		memcpy(&bootmii_cid, otp_data->ng_id, 4);
		logfile("BootMii Console ID: %08x... ", bootmii_cid);
		
		free(otp_data);
		
		printf("OK!\n");
		logfile("OK!");
	} else {
		printf("\nUsing previously loaded BootMii data.\n");
		logfile("\r\nUsing previously loaded BootMii data.\r\n");
	}
	
	if (cntbin_cid != bootmii_cid)
	{
		printf("Error: Console ID mismatch. This content.bin file neither was generated by\nthe Wii the BootMii data came from.\n");
		logfile("Error: Console ID mismatch. This content.bin file neither was generated by the Wii the BootMii data came from.\r\n");
		return -1;
	}
		
	use_bootmii_data = true;
	
	return 0;
}