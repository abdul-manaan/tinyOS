# TinyOS : A basic OS implementation

CPU: RISC-V 32-bit (QEMU emualtor is used to run the OS.)

## GOAL

The goal of is this project is to learn how kernel handles different operations. 
The kernel in this Operating System is very limited, and most of it is very similar to the UNIX OS.


# TinyOS Repository Structure
```
├── common/        # Common code shared between kernel and user space
│   ├── common.c   # Kernel/user common library: printf, memset, etc.
│   ├── common.h   # Kernel/user common library definitions
├── kernel/        # Kernel source files
│   ├── kernel.c   # Kernel: process management, system calls, drivers, etc.
│   ├── kernel.h   # Kernel header file
│   ├── kernel.ld  # Kernel linker script (memory layout definition)
│   ├── fs.c       # File system implementation
│   ├── fs.h       # File system header
│   ├── net.c      # Networking implementation
│   ├── net.h      # Networking header
│   ├── disk.c     # Disk management implementation
│   ├── disk.h     # Disk management header
│   ├── virt.c     # Virtualization support
│   ├── virt.h     # Virtualization support header
│   ├── constants.h # Kernel constants
├── user/          # User-space programs
│   ├── user.c     # User library functions
│   ├── user.h     # User library definitions
│   ├── shell.c    # Command-line shell
│   ├── user.ld    # User linker script
├── disk/          # Disk contents
│   ├── tinyOSSpecs.txt # TinyOS disk specifications
│   ├── hello.txt  # Sample file in the file system
├── Makefile       # Build system configuration
├── run.sh         # Script to build and run the system
├── LICENSE        # License file
├── README.md      # Documentation
```

Let me know if you want any modifications! 🚀

## Features
TinyOS implement the following major features:

1. Multitasking: Switch between processes to allow multiple applications to share the CPU.
    - This is a single CPU OS.
    - Context-Switching is implemented
2. Exception handler: Handle events requiring OS intervention, such as illegal instructions.
3. Paging: Provide an isolated memory address space for each application.
    - Supports Virtual Memory for user applications
4. System calls: Allow applications to call kernel features.
5. Device drivers: Abstract hardware functionalities, such as disk read/write.
6. File system: Manage files on disk
    - Using tar file format
7. Command-line shell: User interface for humans.
    - Support a couple of commands like readfile, writefile etc.
8. A bare-bone network driver
    - Implements UDP using virtio-net-device

## Future Features

1. A proper memory allocator that allows freeing memory.
2. Interrupt handling. Do not busy-wait for disk I/O.
3. A full-fledged file system.


## External Documentation and References

**RISC-V Specifications:**
- [RISC-V Instruction Set Manual](https://riscv.org/technical/specifications/)
- [RISC-V Privileged Architecture Specification](https://riscv.org/technical/specifications/privileged-isa/)

**Virtio Specifications:**
- [Virtio Specification v1.1](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.pdf)

**Operating System Resources:**
- [Operating Systems: Three Easy Pieces](http://pages.cs.wisc.edu/~remzi/OSTEP/)
- [OSDev Wiki](https://wiki.osdev.org/Main_Page)
- [Operating System in 1,000 Lines](https://github.com/1kline/OS)

**Toolchains and Emulators:**
- [RISC-V GNU Toolchain](https://github.com/riscv/riscv-gnu-toolchain)
- [QEMU Emulator](https://www.qemu.org/)


## License

Everything is under MIT Lincese.