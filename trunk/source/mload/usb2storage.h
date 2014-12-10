#ifndef _USBSTORAGE2_H_
#define _USBSTORAGE2_H_

#include <ogc/disc_io.h>
#include <ogc/machine/processor.h>

#define USB_REG_BASE		0x0D040000
#define USB_REG_OP_BASE		(USB_REG_BASE + (read32(USB_REG_BASE) & 0xff))
#define USB_PORT_CONNECTED	(read32(USB_REG_OP_BASE + 0x44) & 0x0F)

#ifdef __cplusplus
extern "C"
{
#endif

	/* Prototypes */
	s32 USBStorage2_Init();
	void USBStorage2_Deinit();
	s32 USBStorage2_GetCapacity(u32 *size);

	s32 USBStorage2_ReadSectors(u32 sector, u32 numSectors, void *buffer);
	s32 USBStorage2_WriteSectors(u32 sector, u32 numSectors, const void *buffer);

#define DEVICE_TYPE_WII_UMS (('W'<<24)|('U'<<16)|('M'<<8)|'S')

	extern const DISC_INTERFACE __io_usbstorage2;

#ifdef __cplusplus
}
#endif

#endif
