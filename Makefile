UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    CC = clang
    OBJCOPY = llvm-objcopy
else
    CC = /opt/homebrew/opt/llvm/bin/clang
    OBJCOPY = /opt/homebrew/opt/llvm/bin/llvm-objcopy
endif

QEMU = qemu-system-riscv32


CFLAGS = -std=c11 -O2 -g3 -Wall -Wextra --target=riscv32 -ffreestanding -nostdlib

# Source files
SHELL_SRC = user/shell.c user/user.c common/common.c
KERNEL_SRC = kernel/kernel.c common/common.c kernel/disk.c kernel/fs.c kernel/virt.c kernel/net.c kernel/interrupttimer.c

USER_LD = user/user.ld
KERNEL_LD = kernel/kernel.ld
# Output files
SHELL_ELF = shell.elf
SHELL_BIN = shell.bin
SHELL_BIN_O = shell.bin.o
KERNEL_ELF = kernel.elf
DISK_TAR = disk.tar

all: clean $(SHELL_ELF) $(KERNEL_ELF) $(DISK_TAR) run

$(SHELL_ELF): $(SHELL_SRC) $(USER_LD)
	$(CC) $(CFLAGS) -Wl,-T$(USER_LD) -Wl,-Map=shell.map -o $@ $(SHELL_SRC)
	$(OBJCOPY) --set-section-flags .bss=alloc,contents -O binary $@ $(SHELL_BIN)
	$(OBJCOPY) -Ibinary -O elf32-littleriscv $(SHELL_BIN) $(SHELL_BIN_O)

$(KERNEL_ELF): $(KERNEL_SRC) $(SHELL_BIN_O) $(KERNEL_LD)
	$(CC) $(CFLAGS) -Wl,-T$(KERNEL_LD) -Wl,-Map=kernel.map -o $@ $(KERNEL_SRC) $(SHELL_BIN_O)

$(DISK_TAR):
	(cd disk && tar cf ../$(DISK_TAR) --format=ustar ./*.txt)

run: $(KERNEL_ELF) $(DISK_TAR)
	$(QEMU) -machine virt -bios default -nographic -serial mon:stdio --no-reboot \
	    -d unimp,guest_errors,int,cpu_reset -D qemu.log  \
	    -drive id=drive0,file=$(DISK_TAR),format=raw,if=none \
	    -device virtio-blk-device,drive=drive0,bus=virtio-mmio-bus.0  \
	    -device virtio-net-device,bus=virtio-mmio-bus.1,netdev=en0 \
	    -netdev type=user,id=en0 \
	    -object filter-dump,id=f0,netdev=en0,file=en0.pcap \
	    -kernel $(KERNEL_ELF)

clean:
	rm -f $(SHELL_ELF) $(SHELL_BIN) $(SHELL_BIN_O) $(KERNEL_ELF) $(DISK_TAR) *.map qemu.log en0.pcap
