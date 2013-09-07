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

void Get_OTP_data()
{
	otp_t *otp_data = memalign(32, sizeof(otp_t));
	
	bool read_otp = OTP_Mount();
	if (!read_otp)
	{
		OTP_Unmount();
		free(otp_data);
		printf("\n\nFatal error: OTP_Mount failed.");
		logfile("\n\nFatal error: OTP_Mount failed.");
		Unmount_Devices();
		Reboot();
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
}
