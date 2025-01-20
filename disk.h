#ifndef DISKHEADERFILE
#define DISKHEADERFILE

#include "kernel.h"
#include "constants.h"


// Virtqueue Descriptor area entry.
struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

// Virtqueue Available Ring.
struct virtq_avail {
    uint16_t flags;
    uint16_t index;
    uint16_t ring[VIRTQ_ENTRY_NUM];
} __attribute__((packed));

// Virtqueue Used Ring entry.
struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

// Virtqueue Used Ring.
struct virtq_used {
    uint16_t flags;
    uint16_t index;
    struct virtq_used_elem ring[VIRTQ_ENTRY_NUM];
} __attribute__((packed));

// Virtqueue.
struct virtio_virtq {
    struct virtq_desc descs[VIRTQ_ENTRY_NUM];
    struct virtq_avail avail;
    struct virtq_used used __attribute__((aligned(PAGE_SIZE)));
    int queue_index;
    volatile uint16_t *used_index;
    uint16_t last_used_index;
} __attribute__((packed));

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



extern struct virtio_virtq *virtq_init(unsigned index) ;

extern void virtio_blk_init(void) ;

// Notifies the device that there is a new request. `desc_index` is the index
// of the head descriptor of the new request.
extern void virtq_kick(struct virtio_virtq *vq, int desc_index);

// Returns whether there are requests being processed by the device.
extern bool virtq_is_busy(struct virtio_virtq *vq) ;

// Reads/writes from/to virtio-blk device.
extern void read_write_disk(void *buf, unsigned sector, int is_write);

#endif // DISKHEADERFILE