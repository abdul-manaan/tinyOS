#pragma once
#include "../common/common.h"
#define CLINT 0x2000000
#define CLINT_MTIMECMP (CLINT + 0x4000)
#define CLINT_MTIME (CLINT + 0xBFF8) // cycles since boot.
#define TIMEBASE_FREQ  10000000  // 10 MHz for QEMU

void timer_init(void);
void timer_interrupt_handler(void);
