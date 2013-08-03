// Copyright 2010 Joseph Jordan <joe.ftpii@psychlaw.com.au>
// This code is licensed to you under the terms of the GNU GPL, version 2;
// see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#ifndef _IOSPATCH_H
#define _IOSPATCH_H

#include <gccore.h>

#define AHBPROT_DISABLED ((*(vu32*)0xcd800064 == 0xFFFFFFFF) ? 1 : 0)

u32 IOSPATCH_Apply();

#endif /* _IOSPATCH_H */
