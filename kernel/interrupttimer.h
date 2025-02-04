/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 2025-02-02--14:31:15
 * Last modified: 2025-02-04--17:30:47
 * All rights reserved.
 */


#pragma once
#include "../common/common.h"
#define CLINT 0x2000000
#define CLINT_MTIMECMP (CLINT + 0x4000)
#define CLINT_MTIME (CLINT + 0xBFF8) // cycles since boot.
#define TIMEBASE_FREQ  10000000  // 10 MHz for QEMU

void timer_init(void);
void timer_interrupt_handler(void);
uint32_t timer_getuptime();
