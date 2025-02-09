/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 2025-01-19--18:18:50
 * Last modified: 2025-02-08--23:30:05
 * All rights reserved.
 */


#include "user.h"

extern char __stack_top[];

/*
 * syscall
 *
 * Performs a system call by invoking the `ecall` instruction.
 *
 * Input:
 *   sysno - System call number.
 *   arg0, arg1, arg2 - Arguments for the system call.
 *
 * Process:
 *   - Loads the arguments into registers `a0`, `a1`, `a2`, and `a3`.
 *   - Executes the `ecall` instruction to request a service from the kernel.
 *   - The return value of the system call is stored in `a0`.
 *
 * Output:
 *   Returns the result of the system call.
 */
int syscall(int sysno, int arg0, int arg1, int arg2) {
    register int a0 __asm__("a0") = arg0;
    register int a1 __asm__("a1") = arg1;
    register int a2 __asm__("a2") = arg2;
    register int a3 __asm__("a3") = sysno;

    __asm__ __volatile__("ecall"
                         : "=r"(a0)
                         : "r"(a0), "r"(a1), "r"(a2), "r"(a3)
                         : "memory");

    return a0;
}

/*
 * putchar
 *
 * Writes a single character to the console.
 *
 * Input:
 *   ch - Character to print.
 *
 * Output:
 *   Character is printed to the standard output.
 */
void putchar(char ch) {
    syscall(SYS_PUTCHAR, ch, 0, 0);
}

/*
 * getchar
 *
 * Reads a single character from the console.
 *
 * Output:
 *   Returns the character read.
 */
int getchar(void) {
    return syscall(SYS_GETCHAR, 0, 0, 0);
}

/*
 * readfile
 *
 * Reads the contents of a file into a buffer.
 *
 * Input:
 *   filename - Name of the file to read.
 *   buf - Buffer to store the file contents.
 *   len - Maximum number of bytes to read.
 *
 * Output:
 *   Returns the number of bytes read.
 */
int readfile(const char *filename, char *buf, int len) {
    return syscall(SYS_READFILE, (int) filename, (int) buf, len);
}

/*
 * writefile
 *
 * Writes data to a file.
 *
 * Input:
 *   filename - Name of the file to write to.
 *   buf - Data to write.
 *   len - Number of bytes to write.
 *
 * Output:
 *   Returns the number of bytes written.
 */
int writefile(const char *filename, const char *buf, int len) {
    return syscall(SYS_WRITEFILE, (int) filename, (int) buf, len);
}

/*
 * freemem
 *
 * Retrieves the amount of free memory available for OS.
 *
 * Output:
 *   Returns the number of free bytes.
 */
size_t freemem() {
    return syscall(SYS_FREEMEM, 0, 0, 0);
}

/*
 * fork
 *
 * Forks the current process.
 *
 * Output:
 *   Returns the child processp pid. Child will get 0.
 */
uint32_t fork() {
    return syscall(SYS_FORK, 0, 0, 0);
}

/*
 * uptime
 *
 * Retrieves the system uptime in seconds.
 *
 * Output:
 *   Returns the system uptime in seconds.
 */
uint32_t uptime() {
    return syscall(SYS_UPTIME, 0, 0, 0) / 1000000;
}


/*
 * getPID
 *
 * Retrieves the process PID.
 *
 * Output:
 *   Returns the process PID.
 */
uint32_t getPID() {
    return syscall(SYS_GETPID, 0, 0, 0) ;
}

/*
 * exit
 *
 * Terminates the current process.
 *
 * Process:
 *   - Invokes the SYS_EXIT system call.
 *   - Enters an infinite loop to prevent further execution.
 *
 * Output:
 *   Never returns.
 */
__attribute__((noreturn)) void exit(void) {
    syscall(SYS_EXIT, 0, 0, 0);
    for (;;);
}

/*
 * start
 *
 * Entry point for the user program.
 *
 * Process:
 *   - Sets the stack pointer to `__stack_top`.
 *   - Calls `main()`.
 *   - Calls `exit()` to terminate if `main()` returns.
 *
 * Output:
 *   Never returns.
 */
__attribute__((section(".text.start")))
__attribute__((naked))
void start(void) {
    __asm__ __volatile__(
        "mv sp, %[stack_top]\n"
        "call main\n"
        "call exit\n" ::[stack_top] "r"(__stack_top));
}