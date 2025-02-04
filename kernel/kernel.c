/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 
 * Last modified: 2025-02-03--19:01:58
 * All rights reserved.
 */

#include "kernel.h"
#include "../common/common.h"
#include "fs.h"
#include "disk.h"
#include "virt.h"
#include "net.h"
#include "interrupttimer.h"

/*
 * External symbols provided by the linker script.
 * These symbols mark the boundaries for different sections in memory.
 */
extern char __bss[], __bss_end[], __stack_top[];
extern char __free_ram[], __free_ram_end[];
extern char __kernel_base[];
extern char _binary_shell_bin_start[], _binary_shell_bin_size[];

/*
 * Process structure definition.
 *
 * Each process contains:
 * - pid: Unique process ID.
 * - state: The current state of the process (e.g., runnable, exited).
 * - sp: The saved stack pointer (used during context switching).
 * - page_table: Pointer to the process's page table for virtual memory mapping.
 * - stack: Dedicated kernel stack for this process.
 */
struct process {
    int pid;
    int state;
    vaddr_t sp;
    uint32_t *page_table;
    uint8_t stack[8192];
};

/* Global process management variables */
struct process *current_proc;  // Pointer to the currently running process.
struct process *idle_proc;     // Pointer to the idle process (runs when no other process is runnable).
struct process procs[PROCS_MAX]; // Array holding all process control structures.

uint64_t uptime = 0; // Global uptime counter (incremented on timer interrupts).

/*
 * alloc_pages: Allocates physical memory pages.
 *
 * Input:
 *   n - Number of pages to allocate.
 *
 * Process:
 *   The function maintains a static pointer (next_paddr) to the next free physical memory address.
 *   It then allocates 'n' pages by incrementing next_paddr and zeroing the allocated memory.
 *
 * Output:
 *   Returns the physical address of the allocated memory.
 *
 * If there is not enough memory, it will panic.
 */
paddr_t alloc_pages(uint32_t n) {
    static paddr_t next_paddr = (paddr_t) __free_ram;
    paddr_t paddr = next_paddr;
    next_paddr += n * PAGE_SIZE;

    if (next_paddr > (paddr_t) __free_ram_end)
        PANIC("out of memory");

    memset((void *) paddr, 0, n * PAGE_SIZE);
    return paddr;
}

/*
 * sbi_call: Performs an SBI (Supervisor Binary Interface) call.
 *
 * The SBI call is used to interface with the underlying hardware from supervisor mode.
 *
 * Input:
 *   arg0 ... arg5: Up to six arguments to pass to the SBI call.
 *   fid: Function identifier (what operation to perform).
 *   eid: Extension identifier (which SBI extension is used).
 *
 * Process:
 *   Registers a0-a7 are used to pass arguments according to the RISC-V calling convention.
 *   The inline assembly triggers an ecall, and the result is returned in registers a0 and a1.
 *
 * Output:
 *   A struct sbiret containing:
 *     - error: Error code (or return value) from the SBI call.
 *     - value: Secondary return value.
 */
struct sbiret sbi_call(long arg0, long arg1, long arg2, long arg3, long arg4,
                       long arg5, long fid, long eid) {
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a3 __asm__("a3") = arg3;
    register long a4 __asm__("a4") = arg4;
    register long a5 __asm__("a5") = arg5;
    register long a6 __asm__("a6") = fid;
    register long a7 __asm__("a7") = eid;

    __asm__ __volatile__("ecall"
                         : "=r"(a0), "=r"(a1)
                         : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
                           "r"(a6), "r"(a7)
                         : "memory");
    return (struct sbiret){.error = a0, .value = a1};
}

/*
 * putchar: Writes a character to the console.
 *
 * Input:
 *   ch - Character to write.
 *
 * Process:
 *   Calls the sbi_call function with the Console Putchar extension.
 *
 * Output:
 *   No direct output (side-effect: character is printed to console).
 */
void putchar(char ch) {
    sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}

/*
 * getchar: Reads a character from the console.
 *
 * Process:
 *   Calls the sbi_call function with the Console Getchar extension.
 *
 * Output:
 *   Returns the read character. If no character is available, the return value may indicate so.
 */
long getchar(void) {
    struct sbiret ret = sbi_call(0, 0, 0, 0, 0, 0, 0, 2);
    return ret.error;
}

/*
 * setup_s_mode_interrupt: Configures the supervisor mode interrupt.
 *
 * Process:
 *   Sets the S-level interrupt enable flag (SIE) in the sstatus register.
 *   This example uses a CSR instruction to enable S interrupts.
 *
 * Note:
 *   The code is commented out in some cases if not needed.
 */
void setup_s_mode_interrupt() {
  __asm__ __volatile__(
      //"csrw stvec, %0\n"  // Uncomment if setting trap vector
      "csrsi sstatus, 2"   // Set SIE flag
      : /* Outputs: none*/
      : /* Inputs: none*/
      : /* Clobbered registers: none*/
      );
}

/*
 * set_timer_in_near_future: Programs a timer interrupt to occur in the near future.
 *
 * Process:
 *   - Reads the current time using the rdtime instruction.
 *   - Adds an offset (here, 10,000,000 cycles) to set a future time.
 *   - Uses an SBI call to set the timer.
 *
 * Output:
 *   Returns a struct sbiret with the status of the timer setting call.
 */
struct sbiret set_timer_in_near_future() {
  struct sbiret return_status;
  
  __asm__ __volatile__(
      "rdtime t0\n\t"         // Read the current time into t0
      "li t1, 10000000\n\t"     // Load immediate value (offset) into t1
      "add a0, t0, t1\n\t"      // Compute future time by adding t1 to current time in t0
      "li a7, 0x54494D45\n\t"   // Load SBI function code for setting timer (magic number)\n"
      "li a6, 0x00\n\t"         // Set extension id to 0\n"
      "ecall\n\t"               // Trigger the ecall to set the timer\n"
      "mv %0, a0\n\t"           // Move return value from a0 to return_status.error\n"
      "mv %1, a1\n\t"           // Move return value from a1 to return_status.value\n"
      : /* Outputs: */ "=r"(return_status.error), "=r"(return_status.value)
      : /* Inputs: none */
      : /* Clobbered registers: */ "a0", "a1", "a6", "a7", "t0", "t1"
      );

  return return_status;
}

/*
 * enable_s_mode_timer_interrupt: Enables timer interrupts in supervisor mode.
 *
 * Process:
 *   Sets the timer interrupt enable bit (STIE) in the sie (interrupt-enable) CSR.
 *
 * Input:
 *   None.
 *
 * Output:
 *   Timer interrupts become enabled.
 */
void enable_s_mode_timer_interrupt() {
  __asm__ __volatile__(
      "li t1, 32\n\t"       // Load immediate value (bit mask for STIE)
      "csrs sie, t1\n"       // Set STIE in the sie register
      ::: /* Clobbered registers: */ "t1"
      );
}

/*
 * clear_timer_pending_bit: Clears the pending timer interrupt flag.
 *
 * Process:
 *   Uses the csrc instruction to clear the timer bit in the sip (interrupt-pending) register.
 *
 * Input:
 *   None.
 *
 * Output:
 *   The timer pending flag is cleared.
 */
void clear_timer_pending_bit() {
  __asm__ __volatile__(
      "li t0, 32\n\t"      // Load immediate value (bit mask for timer pending bit)
      "csrc sip, t0\n"      // Clear the timer pending bit in sip
      ::: /* Clobbered registers: */ "t0"
      );
}

/*
 * s_mode_interrupt_handler: Handles supervisor mode timer interrupts.
 *
 * Process:
 *   - Clears the timer pending flag.
 *   - Prints a timer message along with the uptime counter.
 *   - Sets a new timer in the near future.
 *
 * Attributes:
 *   - 'interrupt("supervisor")': Tells the compiler that this function is an interrupt handler.
 *   - 'section(".text.interrupt")': Places the function in the designated interrupt section.
 *
 * Input:
 *   None (invoked by the hardware interrupt mechanism).
 *
 * Output:
 *   Side-effects: prints a message and resets the timer.
 */
__attribute__((interrupt ("supervisor")))
__attribute__((section (".text.interrupt")))
void s_mode_interrupt_handler(void) {
    clear_timer_pending_bit();       // Clear timer interrupt pending flag.
    printf("timer %d\n", uptime++);   // Print timer message and increment uptime.
    set_timer_in_near_future();       // Program the next timer interrupt.
}

/*
 * yield: Gives up the CPU (used to trigger a context switch).
 *
 * Process:
 *   Searches for a runnable process in the process table.
 *   If one is found (other than the current process), it performs a context switch.
 *
 * Input:
 *   None.
 *
 * Output:
 *   No return value. Side-effect: current process context is switched.
 */
void yield(void);

/*
 * kernel_entry: The entry point for kernel traps/interrupts.
 *
 * Attributes:
 *   - naked: The function does not have the usual prologue/epilogue generated by the compiler.
 *   - aligned(4): Ensures that the function starts at a 4-byte aligned address.
 *
 * Process:
 *   - Retrieves the kernel stack pointer for the current process from the sscratch CSR.
 *   - Saves registers (including general-purpose and temporary registers) to the stack.
 *   - Calls handle_trap to handle the current trap/interrupt.
 *   - Restores registers and returns using sret to resume user or kernel mode execution.
 *
 * Input:
 *   None (invoked by hardware trap/interrupt mechanism).
 *
 * Output:
 *   Side-effect: context is restored/resumed after handling the trap.
 */
__attribute__((naked))
__attribute__((aligned(4)))
void kernel_entry(void) {
    __asm__ __volatile__(
        // Retrieve the current process's kernel stack pointer from sscratch.
        "csrrw sp, sscratch, sp\n"

        // Allocate space on the kernel stack to save registers.
        "addi sp, sp, -4 * 31\n"
        "sw ra,  4 * 0(sp)\n"    // Save return address (ra)
        "sw gp,  4 * 1(sp)\n"    // Save global pointer (gp)
        "sw tp,  4 * 2(sp)\n"    // Save thread pointer (tp)
        "sw t0,  4 * 3(sp)\n"    // Save temporary registers (t0, t1, t2, etc.)
        "sw t1,  4 * 4(sp)\n"
        "sw t2,  4 * 5(sp)\n"
        "sw t3,  4 * 6(sp)\n"
        "sw t4,  4 * 7(sp)\n"
        "sw t5,  4 * 8(sp)\n"
        "sw t6,  4 * 9(sp)\n"
        "sw a0,  4 * 10(sp)\n"   // Save argument registers a0-a7
        "sw a1,  4 * 11(sp)\n"
        "sw a2,  4 * 12(sp)\n"
        "sw a3,  4 * 13(sp)\n"
        "sw a4,  4 * 14(sp)\n"
        "sw a5,  4 * 15(sp)\n"
        "sw a6,  4 * 16(sp)\n"
        "sw a7,  4 * 17(sp)\n"
        "sw s0,  4 * 18(sp)\n"   // Save saved registers s0-s11
        "sw s1,  4 * 19(sp)\n"
        "sw s2,  4 * 20(sp)\n"
        "sw s3,  4 * 21(sp)\n"
        "sw s4,  4 * 22(sp)\n"
        "sw s5,  4 * 23(sp)\n"
        "sw s6,  4 * 24(sp)\n"
        "sw s7,  4 * 25(sp)\n"
        "sw s8,  4 * 26(sp)\n"
        "sw s9,  4 * 27(sp)\n"
        "sw s10, 4 * 28(sp)\n"
        "sw s11, 4 * 29(sp)\n"

        // Save the current stack pointer (at time of exception) into the stack.
        "csrr a0, sscratch\n"
        "sw a0,  4 * 30(sp)\n"

        // Reset the kernel stack by updating sscratch.
        "addi a0, sp, 4 * 31\n"
        "csrw sscratch, a0\n"

        // Pass pointer to saved registers to the trap handler.
        "mv a0, sp\n"
        "call handle_trap\n"

        // Restore registers from the stack.
        "lw ra,  4 * 0(sp)\n"
        "lw gp,  4 * 1(sp)\n"
        "lw tp,  4 * 2(sp)\n"
        "lw t0,  4 * 3(sp)\n"
        "lw t1,  4 * 4(sp)\n"
        "lw t2,  4 * 5(sp)\n"
        "lw t3,  4 * 6(sp)\n"
        "lw t4,  4 * 7(sp)\n"
        "lw t5,  4 * 8(sp)\n"
        "lw t6,  4 * 9(sp)\n"
        "lw a0,  4 * 10(sp)\n"
        "lw a1,  4 * 11(sp)\n"
        "lw a2,  4 * 12(sp)\n"
        "lw a3,  4 * 13(sp)\n"
        "lw a4,  4 * 14(sp)\n"
        "lw a5,  4 * 15(sp)\n"
        "lw a6,  4 * 16(sp)\n"
        "lw a7,  4 * 17(sp)\n"
        "lw s0,  4 * 18(sp)\n"
        "lw s1,  4 * 19(sp)\n"
        "lw s2,  4 * 20(sp)\n"
        "lw s3,  4 * 21(sp)\n"
        "lw s4,  4 * 22(sp)\n"
        "lw s5,  4 * 23(sp)\n"
        "lw s6,  4 * 24(sp)\n"
        "lw s7,  4 * 25(sp)\n"
        "lw s8,  4 * 26(sp)\n"
        "lw s9,  4 * 27(sp)\n"
        "lw s10, 4 * 28(sp)\n"
        "lw s11, 4 * 29(sp)\n"
        "lw sp,  4 * 30(sp)\n"   // Restore original stack pointer.
        "sret\n"                // Return from trap, restoring context.
    );
}

/*
 * handle_syscall: Handles system calls (software interrupts).
 *
 * Input:
 *   f - Pointer to a trap_frame structure which holds CPU register states.
 *
 * Process:
 *   Uses the value in register a3 (in the trap_frame) to determine which syscall was invoked.
 *   For example:
 *     - SYS_PUTCHAR: Write a character to the console.
 *     - SYS_GETCHAR: Read a character from the console.
 *     - SYS_EXIT: Terminate the current process.
 *     - SYS_FREEMEM: Return the number of free memory pages.
 *
 * Output:
 *   Modifies the trap frame with a return value (for example, in a0).
 */
void handle_syscall(struct trap_frame *f) {
    switch (f->a3) {
        case SYS_PUTCHAR:
            putchar(f->a0);
            break;
        case SYS_GETCHAR:
            while (1) {
                long ch = getchar();
                if (ch >= 0) {
                    f->a0 = ch;
                    break;
                }
                yield(); // Yield if no input available, waiting for a character.
            }
            break;
        case SYS_EXIT:
            printf("process %d exited\n", current_proc->pid);
            current_proc->state = PROC_EXITED;
            yield(); // Switch context after exit.
            PANIC("unreachable");
        case SYS_READFILE:
        case SYS_WRITEFILE: {
            // File operations: read or write a file.
            // a0: pointer to filename
            // a1: pointer to buffer
            // a2: length of data
            const char *filename = (const char *) f->a0;
            char *buf = (char *) f->a1;
            int len = f->a2;
            struct file *file = fs_lookup(filename);
            if (!file) {
                printf("file not found: %s\n", filename);
                f->a0 = -1;
                break;
            }
            if (len > (int) sizeof(file->data))
                len = file->size;

            if (f->a3 == SYS_WRITEFILE) {
                memcpy(file->data, buf, len);
                file->size = len;
                fs_flush(); // Flush file system buffers.
            } else {
                memcpy(buf, file->data, len);
            }
            f->a0 = len;
            break;
        }
        case SYS_FREEMEM:
            // Return the number of free pages available.
            f->a0 = ((uint32_t)__free_ram_end - (uint32_t)alloc_pages(0)) / PAGE_SIZE;
            break;
        default:
            PANIC("unexpected syscall a3=%x\n", f->a3);
    }
}

/*
 * handle_trap: Top-level trap handler for exceptions and interrupts.
 *
 * Input:
 *   f - Pointer to a trap_frame containing saved register state.
 *
 * Process:
 *   Reads the cause of the trap from the scause CSR.
 *   Depending on the trap type:
 *     - If it is an ecall (system call), it calls handle_syscall.
 *     - If it is a timer interrupt (scause 0x80000005), it calls the timer handler.
 *     - Otherwise, it panics for an unexpected trap.
 *
 * Output:
 *   Updates the sepc (program counter) CSR so that the process resumes correctly.
 */
void handle_trap(struct trap_frame *f) {
    uint32_t scause = READ_CSR(scause);
    uint32_t stval = READ_CSR(stval);
    uint32_t user_pc = READ_CSR(sepc);
    if (scause == SCAUSE_ECALL) {
        handle_syscall(f);
        user_pc += 4; // Advance program counter past the ecall instruction.
    } else if (scause == 0x80000005) {
        s_mode_interrupt_handler();
    } else {
        PANIC("unexpected trap scause=%x, stval=%x, sepc=%x\n", scause, stval, user_pc);
    }
    WRITE_CSR(sepc, user_pc);
}

/*
 * switch_context: Performs a context switch between two processes.
 *
 * Attributes:
 *   naked: No prologue/epilogue is generated.
 *
 * Input:
 *   prev_sp: Pointer to where the current (old) process's stack pointer should be saved.
 *   next_sp: Pointer to the new process's stack pointer (to load into sp).
 *
 * Process:
 *   - Saves callee-saved registers from the current process onto its stack.
 *   - Saves the current stack pointer (sp) to *prev_sp.
 *   - Loads the new stack pointer from *next_sp.
 *   - Restores callee-saved registers from the new process's stack.
 *   - Returns (using ret), thereby transferring control to the new process.
 *
 * Output:
 *   No return value; control is transferred to the new process.
 */
__attribute__((naked)) void switch_context(uint32_t *prev_sp,
                                           uint32_t *next_sp) {
    __asm__ __volatile__(
        // Allocate space on the stack for 13 registers.
        "addi sp, sp, -13 * 4\n"
        // Save callee-saved registers (ra and s0-s11).
        "sw ra,  0  * 4(sp)\n"
        "sw s0,  1  * 4(sp)\n"
        "sw s1,  2  * 4(sp)\n"
        "sw s2,  3  * 4(sp)\n"
        "sw s3,  4  * 4(sp)\n"
        "sw s4,  5  * 4(sp)\n"
        "sw s5,  6  * 4(sp)\n"
        "sw s6,  7  * 4(sp)\n"
        "sw s7,  8  * 4(sp)\n"
        "sw s8,  9  * 4(sp)\n"
        "sw s9,  10 * 4(sp)\n"
        "sw s10, 11 * 4(sp)\n"
        "sw s11, 12 * 4(sp)\n"

        // Save the current stack pointer to *prev_sp.
        "sw sp, (a0)\n"
        // Load new stack pointer from *next_sp.
        "lw sp, (a1)\n"

        // Restore callee-saved registers from the new process's stack.
        "lw ra,  0  * 4(sp)\n"
        "lw s0,  1  * 4(sp)\n"
        "lw s1,  2  * 4(sp)\n"
        "lw s2,  3  * 4(sp)\n"
        "lw s3,  4  * 4(sp)\n"
        "lw s4,  5  * 4(sp)\n"
        "lw s5,  6  * 4(sp)\n"
        "lw s6,  7  * 4(sp)\n"
        "lw s7,  8  * 4(sp)\n"
        "lw s8,  9  * 4(sp)\n"
        "lw s9,  10 * 4(sp)\n"
        "lw s10, 11 * 4(sp)\n"
        "lw s11, 12 * 4(sp)\n"
        "addi sp, sp, 13 * 4\n"  // Adjust sp to remove saved registers.
        "ret\n"
    );
}

/*
 * map_page: Maps a virtual address to a physical address in a given page table.
 *
 * Input:
 *   table1 - Pointer to the first-level page table.
 *   vaddr  - Virtual address to map.
 *   paddr  - Physical address to map to.
 *   flags  - Permission and status flags (e.g., read, write, execute, valid).
 *
 * Process:
 *   - Validates that both vaddr and paddr are aligned to a page boundary.
 *   - Calculates the index into the first-level page table (vpn1).
 *   - If the second-level page table is not yet allocated, it allocates one.
 *   - Calculates the index (vpn0) into the second-level page table.
 *   - Sets the second-level page table entry with the physical address and flags.
 *
 * Output:
 *   No return value; side-effect is updating the page table.
 */
void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
    if (!is_aligned(vaddr, PAGE_SIZE))
        PANIC("unaligned vaddr %x", vaddr);

    if (!is_aligned(paddr, PAGE_SIZE))
        PANIC("unaligned paddr %x", paddr);

    // Calculate first-level table index (vpn1).
    uint32_t vpn1 = (vaddr >> 22) & 0x3ff;
    if ((table1[vpn1] & PAGE_V) == 0) {
        // If no second-level page table exists, allocate one.
        uint32_t pt_paddr = alloc_pages(1);
        table1[vpn1] = ((pt_paddr / PAGE_SIZE) << 10) | PAGE_V;
    }

    // Calculate second-level table index (vpn0).
    uint32_t vpn0 = (vaddr >> 12) & 0x3ff;
    // Get pointer to the second-level page table.
    uint32_t *table0 = (uint32_t *) ((table1[vpn1] >> 10) * PAGE_SIZE);
    // Set the entry with the physical address and flags.
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

/*
 * user_entry: Entry point for user processes.
 *
 * Attributes:
 *   naked: No prologue/epilogue code is generated.
 *
 * Process:
 *   - Sets the sepc (exception program counter) to USER_BASE, the starting address for user code.
 *   - Updates sstatus to enable interrupts and allow user memory access.
 *   - Uses sret to return to user mode, beginning execution at USER_BASE.
 *
 * Input:
 *   None.
 *
 * Output:
 *   No return value. Side-effect: Control is transferred to the user process.
 */
__attribute__((naked)) 
void user_entry(void) {
    __asm__ __volatile__(
        "csrw sepc, %[sepc]        \n"      // Set the user program counter.
        "csrw sstatus, %[sstatus]  \n"      // Set sstatus for user mode execution.
        "sret                      \n"      // Return from supervisor to user mode.
        :
        : [sepc] "r" (USER_BASE),
          [sstatus] "r" (SSTATUS_SPIE | SSTATUS_SUM) // Enable interrupts and user memory access.
    );
}

/*
 * create_process: Creates a new process from a given image.
 *
 * Input:
 *   image      - Pointer to the binary image of the process.
 *   image_size - Size (in bytes) of the binary image.
 *
 * Process:
 *   - Searches for an unused process slot.
 *   - Initializes the process's kernel stack with default values and sets the return address to user_entry.
 *   - Allocates a new page table and maps kernel pages (for the kernel to function in user mode).
 *   - Maps the virtual addresses for I/O regions (like virtio-blk and virtio-net) for device access.
 *   - Allocates pages for the user process and copies the binary image into these pages.
 *
 * Output:
 *   Returns a pointer to the newly created process control structure.
 */
struct process *create_process(const void *image, size_t image_size) {
    struct process *proc = NULL;
    int i;
    // Find an unused process slot.
    for (i = 0; i < PROCS_MAX; i++) {
        if (procs[i].state == PROC_UNUSED) {
            proc = &procs[i];
            break;
        }
    }
    if (!proc)
        PANIC("no free process slots");

    // Initialize the process's kernel stack with callee-saved registers.
    uint32_t *sp = (uint32_t *) &proc->stack[sizeof(proc->stack)];
    *--sp = 0;                      // s11
    *--sp = 0;                      // s10
    *--sp = 0;                      // s9
    *--sp = 0;                      // s8
    *--sp = 0;                      // s7
    *--sp = 0;                      // s6
    *--sp = 0;                      // s5
    *--sp = 0;                      // s4
    *--sp = 0;                      // s3
    *--sp = 0;                      // s2
    *--sp = 0;                      // s1
    *--sp = 0;                      // s0
    *--sp = (uint32_t) user_entry;  // ra (set to start at user_entry)

    // Allocate a new page table for the process.
    uint32_t *page_table = (uint32_t *) alloc_pages(1);
    // Map all kernel pages so that the process has access to kernel code/data.
    for (paddr_t paddr = (paddr_t) __kernel_base;
         paddr < (paddr_t) __free_ram_end; paddr += PAGE_SIZE)
        map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);

    // Map the virtio-blk and virtio-net MMIO regions for device I/O.
    map_page(page_table, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R | PAGE_W);
    map_page(page_table, VIRTIO_NET_PADDR, VIRTIO_NET_PADDR, PAGE_R | PAGE_W);

    // Map user pages and copy the binary image into them.
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
        paddr_t page = alloc_pages(1);
        // Calculate how many bytes to copy for the current page.
        size_t remaining = image_size - off;
        size_t copy_size = PAGE_SIZE <= remaining ? PAGE_SIZE : remaining;
        memcpy((void *) page, image + off, copy_size);
        map_page(page_table, USER_BASE + off, page,
                 PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }

    proc->pid = i + 1;              // Assign a unique process ID.
    proc->state = PROC_RUNNABLE;      // Mark process as runnable.
    proc->sp = (uint32_t) sp;         // Save the current stack pointer for context switching.
    proc->page_table = page_table;    // Save the allocated page table.
    return proc;
}

/*
 * delay: A simple delay loop.
 *
 * Process:
 *   Executes a loop with NOP (no operation) instructions to waste time.
 *
 * Input:
 *   None.
 *
 * Output:
 *   No return value; side-effect is a delay.
 */
void delay(void) {
    for (int i = 0; i < 30000000; i++)
        __asm__ __volatile__("nop"); // Do nothing.
}

/*
 * yield: Searches for a runnable process and switches context to it.
 *
 * Process:
 *   - Iterates over the process table to find a runnable process (other than the current one).
 *   - If found, updates the SATP and sscratch registers with the new process's page table and stack.
 *   - Calls switch_context to perform the actual context switch.
 *
 * Input:
 *   None.
 *
 * Output:
 *   No return value; side-effect: context is switched to another process.
 */
void yield(void) {
    // Search for a runnable process.
    struct process *next = idle_proc;
    for (int i = 0; i < PROCS_MAX; i++) {
        struct process *proc = &procs[(current_proc->pid + i) % PROCS_MAX];
        if (proc->state == PROC_RUNNABLE && proc->pid > 0) {
            next = proc;
            break;
        }
    }

    // If only the current process is runnable, continue executing.
    if (next == current_proc)
        return;

    // Update SATP (address translation) with the new process's page table.
    __asm__ __volatile__(
        "sfence.vma\n"   // Synchronize the virtual memory system.
        "csrw satp, %[satp]\n"
        "sfence.vma\n"
        "csrw sscratch, %[sscratch]\n"
        :
        : [satp] "r" (SATP_SV32 | ((uint32_t) next->page_table / PAGE_SIZE)),
          [sscratch] "r" ((uint32_t) &next->stack[sizeof(next->stack)])
    );

    // Perform context switch.
    struct process *prev = current_proc;
    current_proc = next;
    switch_context(&prev->sp, &next->sp);
}

/*
 * kernel_main: The main function for the kernel.
 *
 * Process:
 *   - Clears the .bss section.
 *   - Sets up the trap handler (stvec) to point to kernel_entry.
 *   - Initializes devices: virtio block, virtio network.
 *   - Initializes the file system.
 *   - Reads/writes data from/to disk.
 *   - Sets up an idle process.
 *   - Creates a shell process from a binary image.
 *   - Calls yield to begin process scheduling.
 *
 * Input:
 *   None.
 *
 * Output:
 *   Should never return. If it does, PANIC is invoked.
 */
void kernel_main(void) {
    // Clear the .bss section (zero-initialize global variables).
    memset(__bss, 0, (size_t) __bss_end - (size_t) __bss);

    printf("\n\n");

    // Set the supervisor trap vector to the kernel_entry function.
    WRITE_CSR(stvec, (uint32_t) kernel_entry);

    // Initialize hardware devices.
    virtio_blk_init();
    virtio_net_init();
    fs_init();

    // enable_s_mode_timer_interrupt();
    // set_timer_in_near_future();

    // Example disk operations: read first sector and print its contents.
    char buf[SECTOR_SIZE];
    read_write_disk(buf, 0, false /* read from the disk */);
    printf("first sector: %s\n", buf);

    // Write a message to the first sector of the disk.
    strcpy(buf, "hello from kernel!!!\n");
    read_write_disk(buf, 0, true /* write to the disk */);

    // Test DNS functionality (if implemented).
    test_dns();

    // Create the idle process.
    idle_proc = create_process(NULL, 0); // No user image for the idle process.
    idle_proc->pid = -1; // Mark idle process with a special pid.
    current_proc = idle_proc;

    // Create a shell process using a preloaded binary image.
    create_process(_binary_shell_bin_start, (size_t) _binary_shell_bin_size);

    // Start process scheduling by yielding the CPU.
    yield();
    PANIC("switched to idle process");
}

/*
 * boot: The initial entry point of the kernel (called from bootloader).
 *
 * Attributes:
 *   section(".text.boot"): Places this function in the boot section.
 *   naked: No prologue/epilogue code is generated.
 *
 * Process:
 *   - Sets the stack pointer to the top of the kernel stack.
 *   - Jumps to kernel_main to begin kernel initialization.
 *
 * Input:
 *   None.
 *
 * Output:
 *   No return value; control is transferred to kernel_main.
 */
__attribute__((section(".text.boot")))
__attribute__((naked))
void boot(void) {
    __asm__ __volatile__(
        "mv sp, %[stack_top]\n" // Set the stack pointer to __stack_top.
        "j kernel_main\n"       // Jump to kernel_main.
        :
        : [stack_top] "r" (__stack_top)
    );
}
