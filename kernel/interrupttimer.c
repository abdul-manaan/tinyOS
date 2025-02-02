#include "interrupttimer.h"
#include "kernel.h"

void timer_init() {
    // uint32_t now = *(uint32_t*)CLINT_MTIME;
    // *(uint32_t*)CLINT_MTIMECMP = now + TIMEBASE_FREQ;  // Set next interrupt 1 second later

    // Enable machine timer interrupts
    uint32_t sstatus, sie;
    __asm__ __volatile__("csrr %0, sstatus" : "=r"(sstatus));
    __asm__ __volatile__("csrs sstatus, %0" :: "r"(sstatus | (1<<1)));
    __asm__ __volatile__("csrr %0, sie" : "=r"(sie));
    __asm__ __volatile__("csrs sie, %0" :: "r"(sie | (1<<5)));
    // settimer();
}

volatile uint32_t now = 0;

void timer_interrupt_handler() {
    // uint64_t now = *(uint32_t*)CLINT_MTIME;
    // *(uint32_t*)CLINT_MTIMECMP = now + TIMEBASE_FREQ;  // Schedule next interrupt

    printf("Uptime: %d seconds\n",now++);
    // settimer();
}
