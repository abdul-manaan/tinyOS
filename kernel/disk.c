/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 2025-01-20--16:47:18
 * Last modified: 2025-02-04--17:45:26
 * All rights reserved.
 */


#include "disk.h"

struct virtio_virtq *blk_request_vq;
struct virtio_blk_req *blk_req;
paddr_t blk_req_paddr;
unsigned blk_capacity;

/*
 * virtio_reg_read32
 *
 * Reads a 32-bit value from a given virtio register.
 *
 * Input:
 *   offset - Offset from the base address of the virtio block device.
 *
 * Output:
 *   Returns the 32-bit value read from the register.
 */
uint32_t virtio_reg_read32(unsigned offset) {
    return *((volatile uint32_t *) (VIRTIO_BLK_PADDR + offset));
}

/*
 * virtio_reg_read64
 *
 * Reads a 64-bit value from a given virtio register.
 *
 * Input:
 *   offset - Offset from the base address of the virtio block device.
 *
 * Output:
 *   Returns the 64-bit value read from the register.
 */
uint64_t virtio_reg_read64(unsigned offset) {
    return *((volatile uint64_t *) (VIRTIO_BLK_PADDR + offset));
}

/*
 * virtio_reg_write32
 *
 * Writes a 32-bit value to a given virtio register.
 *
 * Input:
 *   offset - Offset from the base address of the virtio block device.
 *   value  - 32-bit value to write.
 */
void virtio_reg_write32(unsigned offset, uint32_t value) {
    *((volatile uint32_t *) (VIRTIO_BLK_PADDR + offset)) = value;
}

/*
 * virtio_reg_fetch_and_or32
 *
 * Reads a 32-bit value from a virtio register, performs a bitwise OR operation,
 * and writes the result back to the register.
 *
 * Input:
 *   offset - Offset from the base address of the virtio block device.
 *   value  - Value to OR with the current register value.
 */
void virtio_reg_fetch_and_or32(unsigned offset, uint32_t value) {
    virtio_reg_write32(offset, virtio_reg_read32(offset) | value);
}

/*
 * virtq_blk_init
 *
 * Initializes a virtqueue for the virtio block device.
 *
 * Input:
 *   index - Index of the virtqueue to initialize.
 *
 * Process:
 *   - Allocates memory for the virtqueue structure.
 *   - Configures the virtqueue registers in the virtio device.
 *
 * Output:
 *   Returns a pointer to the initialized virtqueue.
 */
struct virtio_virtq *virtq_blk_init(unsigned index) {
    paddr_t virtq_paddr = alloc_pages(align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    struct virtio_virtq *vq = (struct virtio_virtq *) virtq_paddr;
    vq->queue_index = index;
    vq->used_index = (volatile uint16_t *) &vq->used.index;

    virtio_reg_write32(VIRTIO_REG_QUEUE_SEL, index);
    virtio_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);
    virtio_reg_write32(VIRTIO_REG_QUEUE_ALIGN, 0);
    virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, virtq_paddr);

    return vq;
}

/*
 * virtio_blk_init
 *
 * Initializes the virtio block device.
 *
 * Process:
 *   - Verifies the device's magic number, version, and device ID.
 *   - Performs the necessary handshake to initialize the device.
 *   - Allocates memory for the request queue and stores device capacity.
 */
void virtio_blk_init(void) {
    if (virtio_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976)
        PANIC("virtio: invalid magic value");
    if (virtio_reg_read32(VIRTIO_REG_VERSION) != 1)
        PANIC("virtio: invalid version");
    if (virtio_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK)
        PANIC("virtio: invalid device id");

    virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FEAT_OK);
    
    blk_request_vq = virtq_blk_init(0);
    virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

    blk_capacity = virtio_reg_read64(VIRTIO_REG_DEVICE_CONFIG) * SECTOR_SIZE;
    printf("virtio-blk: capacity is %d bytes\n", blk_capacity);

    blk_req_paddr = alloc_pages(align_up(sizeof(*blk_req), PAGE_SIZE) / PAGE_SIZE);
    blk_req = (struct virtio_blk_req *) blk_req_paddr;
}

/*
 * virtq_kick
 *
 * Notifies the virtio block device that a new request is available.
 *
 * Input:
 *   vq         - Pointer to the virtqueue.
 *   desc_index - Index of the head descriptor of the new request.
 */
void virtq_kick(struct virtio_virtq *vq, int desc_index) {
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc_index;
    vq->avail.index++;
    __sync_synchronize();
    virtio_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
    vq->last_used_index++;
}

/*
 * read_write_disk
 *
 * Performs a read or write operation on the virtio block device.
 *
 * Input:
 *   buf      - Buffer to read data into or write data from.
 *   sector   - Sector number to read or write.
 *   is_write - 1 for write operation, 0 for read operation.
 *
 * Process:
 *   - Constructs a virtio block request with the specified operation.
 *   - Configures the virtqueue descriptors.
 *   - Notifies the device and waits for completion.
 *
 * Output:
 *   On success, the buffer is updated with read data (if applicable).
 *   On failure, an error message is printed.
 */
void read_write_disk(void *buf, unsigned sector, int is_write) {
    if (sector >= blk_capacity / SECTOR_SIZE) {
        printf("virtio: tried to read/write sector=%d, but capacity is %d\n",
              sector, blk_capacity / SECTOR_SIZE);
        return;
    }

    blk_req->sector = sector;
    blk_req->type = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    if (is_write)
        memcpy(blk_req->data, buf, SECTOR_SIZE);

    struct virtio_virtq *vq = blk_request_vq;
    vq->descs[0].addr = blk_req_paddr;
    vq->descs[0].len = sizeof(uint32_t) * 2 + sizeof(uint64_t);
    vq->descs[0].flags = VIRTQ_DESC_F_NEXT;
    vq->descs[0].next = 1;

    vq->descs[1].addr = blk_req_paddr + offsetof(struct virtio_blk_req, data);
    vq->descs[1].len = SECTOR_SIZE;
    vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE);
    vq->descs[1].next = 2;

    vq->descs[2].addr = blk_req_paddr + offsetof(struct virtio_blk_req, status);
    vq->descs[2].len = sizeof(uint8_t);
    vq->descs[2].flags = VIRTQ_DESC_F_WRITE;

    virtq_kick(vq, 0);

    while (virtq_is_busy(vq))
        ;

    if (blk_req->status != 0) {
        printf("virtio: warn: failed to read/write sector=%d status=%d\n",
               sector, blk_req->status);
        return;
    }

    if (!is_write)
        memcpy(buf, blk_req->data, SECTOR_SIZE);
}
