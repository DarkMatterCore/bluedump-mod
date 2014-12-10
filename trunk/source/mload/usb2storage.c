/*-------------------------------------------------------------

 usbstorage_starlet.c -- USB mass storage support, inside starlet
 Copyright (C) 2011 Dimok
 Copyright (C) 2011 Rodries
 Copyright (C) 2009 Kwiirk

 If this driver is linked before libogc, this will replace the original
 usbstorage driver by svpe from libogc
 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any
 damages arising from the use of this software.

 Permission is granted to anyone to use this software for any
 purpose, including commercial applications, and to alter it and
 redistribute it freely, subject to the following restrictions:

 1.  The origin of this software must not be misrepresented; you
 must not claim that you wrote the original software. If you use
 this software in a product, an acknowledgment in the product
 documentation would be appreciated but is not required.

 2.  Altered source versions must be plainly marked as such, and
 must not be misrepresented as being the original software.

 3.  This notice may not be removed or altered from any source
 distribution.

 -------------------------------------------------------------*/
/**************************************************************
* Modified by DarkMatterCore [PabloACZ]                       *
***************************************************************/

#include <gccore.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include "usb2storage.h"

/* IOCTL commands */
#define UMS_BASE						(('U'<<24)|('M'<<16)|('S'<<8))
#define USB_IOCTL_UMS_INIT				(UMS_BASE+0x1)
#define USB_IOCTL_UMS_GET_CAPACITY		(UMS_BASE+0x2)
#define USB_IOCTL_UMS_READ_SECTORS		(UMS_BASE+0x3)
#define USB_IOCTL_UMS_WRITE_SECTORS		(UMS_BASE+0x4)

#define MAX_SECTOR_SIZE					4096
#define MAX_BUFFER_SECTORS				64
#define UMS_HEAPSIZE					2*1024

/* Variables */
static char fs[] ATTRIBUTE_ALIGN(32) = "/dev/usb2";
static char fs2[] ATTRIBUTE_ALIGN(32) = "/dev/usb123";
static char fs3[] ATTRIBUTE_ALIGN(32) = "/dev/usb/ehc";

static s32 hid = -1, fd = -1;
bool hddInUse = false;
u32 hdd_sector_size = 512;

s32 USBStorage2_Init()
{
	if (hddInUse) return 0;
	
	/* Create heap */
	if (hid < 0)
	{
		hid = iosCreateHeap(UMS_HEAPSIZE);
		if (hid < 0) return IPC_ENOMEM;
	}
	
	/* Open USB device */
	if (fd < 0) fd = IOS_Open(fs, 0);
	if (fd < 0) fd = IOS_Open(fs2, 0);
	if (fd < 0) fd = IOS_Open(fs3, 0);
	if (fd < 0) return fd;
	
	/* Initialize USB storage */
	s32 ret = IOS_IoctlvFormat(hid, fd, USB_IOCTL_UMS_INIT, ":");
	if (ret >= 0)
	{
		/* Get device capacity */
		ret = USBStorage2_GetCapacity(&hdd_sector_size);
		if (ret <= 0) ret = IPC_ENOENT;
	}
	
	if (ret < 0)
	{
		USBStorage2_Deinit();
	} else {
		hddInUse = true;
	}
	
	return ret;
}

void USBStorage2_Deinit()
{
	/* Close USB device */
	if (fd >= 0)
	{
		IOS_Close(fd);
		fd = -1;
	}
}

s32 USBStorage2_GetCapacity(u32 *_sector_size)
{
	if (fd >= 0)
	{
		s32 ret;
		u32 sector_size = 0;
		
		ret = IOS_IoctlvFormat(hid, fd, USB_IOCTL_UMS_GET_CAPACITY, ":i", &sector_size);
		if (ret && _sector_size) *_sector_size = sector_size;
		
		return ret;
	}
	
	return IPC_ENOENT;
}

s32 USBStorage2_ReadSectors(u32 sector, u32 numSectors, void *buffer)
{
	u8 *buf = (u8 *) buffer;
	s32 ret = -1;
	
	/* Device not opened */
	if (fd < 0) return fd;
	
	s32 read_secs, read_size;
	while (numSectors > 0)
	{
		read_secs = ((numSectors > MAX_BUFFER_SECTORS) ? MAX_BUFFER_SECTORS : numSectors);
		read_size = (read_secs * hdd_sector_size);
		
		/* Read data */
		ret = IOS_IoctlvFormat(hid, fd, USB_IOCTL_UMS_READ_SECTORS, "ii:d", sector, read_secs, buf, read_size);
		if (ret < 0) break;
		
		sector += read_secs;
		numSectors -= read_secs;
		buf += read_size;
	}
	
	return ret;
}

s32 USBStorage2_WriteSectors(u32 sector, u32 numSectors, const void *buffer)
{
	u8 *buf = (u8 *) buffer;
	s32 ret = -1;
	
	/* Device not opened */
	if (fd < 0) return fd;
	
	s32 write_size, write_secs;
	while (numSectors > 0)
	{
		write_secs = ((numSectors > MAX_BUFFER_SECTORS) ? MAX_BUFFER_SECTORS : numSectors);
		write_size = (write_secs * hdd_sector_size);
		
		/* Write data */
		ret = IOS_IoctlvFormat(hid, fd, USB_IOCTL_UMS_WRITE_SECTORS, "ii:d", sector, write_secs, buf, write_size);
		if (ret < 0) break;
		
		sector += write_secs;
		numSectors -= write_secs;
		buf += write_size;
	}
	
	return ret;
}

static bool __usbstorage_Startup(void)
{
	return  (USBStorage2_Init() >= 0);
}

static bool __usbstorage_IsInserted(void)
{
	return (USBStorage2_GetCapacity(NULL) > 0);
}

static bool __usbstorage_ReadSectors(u32 sector, u32 numSectors, void *buffer)
{
	return (USBStorage2_ReadSectors(sector, numSectors, buffer) >= 0);
}

static bool __usbstorage_WriteSectors(u32 sector, u32 numSectors, const void *buffer)
{
	return (USBStorage2_WriteSectors(sector, numSectors, buffer) >= 0);
}

static bool __usbstorage_ClearStatus(void)
{
	return true;
}

static bool __usbstorage_Shutdown(void)
{
	hddInUse = false;
	hdd_sector_size = 512;
	USBStorage2_Deinit();
	return true;
}

const DISC_INTERFACE __io_usbstorage2 = {
	DEVICE_TYPE_WII_UMS, FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE | FEATURE_WII_USB,
	(FN_MEDIUM_STARTUP) &__usbstorage_Startup,
	(FN_MEDIUM_ISINSERTED) &__usbstorage_IsInserted,
	(FN_MEDIUM_READSECTORS) &__usbstorage_ReadSectors,
	(FN_MEDIUM_WRITESECTORS) &__usbstorage_WriteSectors,
	(FN_MEDIUM_CLEARSTATUS) &__usbstorage_ClearStatus,
	(FN_MEDIUM_SHUTDOWN) &__usbstorage_Shutdown
};
