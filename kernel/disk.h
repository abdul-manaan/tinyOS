#pragma once

#include "kernel.h"
#include "constants.h"
#include "virt.h"

struct virtio_blk_req {
    // First descriptor: read-only from the device
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;

    // Second descriptor: writable by the device if it's a read operation (VIRTQ_DESC_F_WRITE)
    uint8_t data[512];

    // Third descriptor: writable by the device (VIRTQ_DESC_F_WRITE)
    uint8_t status;
} __attribute__((packed));

extern uint32_t virtio_reg_read32(unsigned offset) ;
extern uint64_t virtio_reg_read64(unsigned offset) ;
extern void virtio_reg_write32(unsigned offset, uint32_t value);
extern void virtio_reg_fetch_and_or32(unsigned offset, uint32_t value) ;

extern struct virtio_virtq *virtq_blk_init(unsigned index) ;

extern void virtio_blk_init(void) ;

// Notifies the device that there is a new request. `desc_index` is the index
// of the head descriptor of the new request.
extern void virtq_kick(struct virtio_virtq *vq, int desc_index);
// Reads/writes from/to virtio-blk device.
extern void read_write_disk(void *buf, unsigned sector, int is_write);