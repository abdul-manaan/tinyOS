# TinyOS : A basic OS implementation

CPU: RISC-V 32-bit (QEMU emualtor is used to run the OS.)

## GOAL

The goal of is this project is to learn how kernel handles different operations. 
The kernel in this Operating System is very limited, and most of it is very similar to the UNIX OS.


## Repository Structure
```
├── disk/     - File system contents
├── common.c  - Kernel/user common library: printf, memset, ...
├── common.h  - Kernel/user common library: definitions of structs and constants
├── kernel.c  - Kernel: process management, system calls, device drivers, file system
├── kernel.h  - Kernel: definitions of structs and constants
├── kernel.ld - Kernel: linker script (memory layout definition)
├── shell.c   - Command-line shell
├── user.c    - User library: functions for system calls
├── user.h    - User library: definitions of structs and constants
├── user.ld   - User: linker script (memory layout definition)
└── run.sh    - Build script
```

## Features
TinyOS implement the following major features:

1. Multitasking: Switch between processes to allow multiple applications to share the CPU.
2. Exception handler: Handle events requiring OS intervention, such as illegal instructions.
3. Paging: Provide an isolated memory address space for each application.
4. System calls: Allow applications to call kernel features.
5. Device drivers: Abstract hardware functionalities, such as disk read/write.
6. File system: Manage files on disk.
7. Command-line shell: User interface for humans.

## Future Features

1. A proper memory allocator that allows freeing memory.
2. Interrupt handling. Do not busy-wait for disk I/O.
3. A full-fledged file system. Implementing ext2 would be a good start.
4. Network communication (UDP/TCP/IP).

## Credits

Some of this code and ideas (at-least all the basic features) are taken from **Operating System in 1,000 Lines**.
Link: https://operating-system-in-1000-lines.vercel.app/en/

## License

Everything is under MIT Lincese.