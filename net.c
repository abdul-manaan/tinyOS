
#include "net.h"

struct virtio_virtq *net_vq_tx;
struct virtio_virtq *net_vq_rx;
struct virtio_virtq *net_request_vq; // to be deleted
struct virtio_net_hdr net_rx_head[VIRTQ_ENTRY_NUM];

struct virtio_net_config *net_configuration;
paddr_t net_req_paddr;
unsigned net_capacity;

#define NUM_QUEUES 2

uint32_t virtio_net_reg_read32(unsigned offset) {
    return *((volatile uint32_t *) (VIRTIO_NET_PADDR + offset));
}

uint64_t virtio_net_reg_read64(unsigned offset) {
    return *((volatile uint64_t *) (VIRTIO_NET_PADDR + offset));
}

void virtio_net_reg_write32(unsigned offset, uint32_t value) {
    *((volatile uint32_t *) (VIRTIO_NET_PADDR + offset)) = value;
}

void virtio_net_reg_fetch_and_or32(unsigned offset, uint32_t value) {
    virtio_net_reg_write32(offset, virtio_net_reg_read32(offset) | value);
}

static inline void
fill_desc(struct virtq_desc *desc, uint64_t addr, uint32_t len, uint16_t flags, uint16_t next)
{
  volatile struct virtq_desc *pt = (volatile struct virtq_desc *)desc;
  pt->addr = addr;
  pt->len = len;
  pt->flags = flags;
  pt->next = next;
  __sync_synchronize();
}

static inline void
fill_avail(struct virtq_avail *avail, uint16_t idx)
{
  volatile struct virtq_avail *pt = (volatile struct virtq_avail *)avail;
  pt->ring[avail->index % VIRTQ_ENTRY_NUM] = idx;
  pt->index++;
  __sync_synchronize();
}

struct virtio_virtq  *init_net_virtq(unsigned index) {
    paddr_t virtq_paddr = alloc_pages(align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    struct virtio_virtq *vq = (struct virtio_virtq *) virtq_paddr;
    vq->queue_index = index;
    vq->used_index = (volatile uint16_t *) &vq->used.index;

    virtio_net_reg_write32(VIRTIO_REG_QUEUE_SEL, index);
    printf("1. queue %d STATUS: %d\n", index, virtio_net_reg_read32(VIRTIO_REG_QUEUE_READY));

    if(virtio_net_reg_read32(VIRTIO_REG_QUEUE_READY))
        PANIC("virtio net should not be ready");

    uint32_t max = virtio_net_reg_read32(VIRTIO_REG_QUEUE_NUM_MAX);
    if(max == 0)
        PANIC("virtio net has no queue");
    if(max < NUM_QUEUES)
        PANIC("virtio net max queue too short");

      // set queue size.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);

    // // 6. Notify the device about the used alignment by writing its value in bytes to QueueAlign.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_ALIGN, 0);
    // // 7. Write the physical number of the first page of the queue to the QueuePFN register.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_PFN, virtq_paddr);

    if(index == 0) {
        for(int i = 0; i < VIRTQ_ENTRY_NUM; i++) {
            fill_desc(&vq->descs[i], (uint64_t)&net_rx_head[i],
                    sizeof(struct virtio_net_hdr), 2, 0);
            fill_avail(&vq->avail, i);
        }
    }

      // write physical addresses.
    virtio_net_reg_write32(VIRTQ_MMIO_DESC, (uint32_t)vq->descs);
    virtio_net_reg_write32(VIRTQ_DRIVER_DESC, (uint32_t)&vq->avail);
    virtio_net_reg_write32(VIRTQ_DEVICE_DESC, (uint32_t)&vq->used);

    // queue is ready.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_READY, 0x1);
    printf("2. queue %d STATUS: %d\n", index, virtio_net_reg_read32(VIRTIO_REG_QUEUE_READY));

    return vq;
}

void virtq_net_init() {
    // Allocate a region for the virtqueue.
    printf("VIRTIO_REG_DEVICE_ID: %x\n", virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID));
    printf("VIRTIO_REG_VENDOR_ID: %x\n", virtio_net_reg_read32(VIRTIO_REG_VENDOR_ID));

      // initialize the virtio device
    if(virtio_net_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976 ||
        virtio_net_reg_read32(VIRTIO_REG_VERSION) != 1 ||
        virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_NET ||
        virtio_net_reg_read32(VIRTIO_REG_VENDOR_ID) != 0x554d4551) {
        PANIC("could not find virtio net");
    }

    // RESET THE DEVICE
    virtio_net_reg_write32(VIRTIO_REG_DEVICE_STATUS,0);

     // set ACKNOWLEDGE status bit
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);

      // set DRIVER status bit
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);

      // negotiate features
    uint32_t device_features = virtio_net_reg_read32(VIRTIO_REG_DEVICE_FEATURES);
    // features &= ~(1 << VIRTIO_NET_F_MAC);
    // features &= ~(1 << VIRTIO_NET_F_STATUS);
    printf("virtio-net: device feature is %x\n", device_features);
    uint32_t driver_features = VIRTIO_NET_F_MTU | VIRTIO_NET_F_MAC | VIRTIO_NET_F_CSUM;
    printf("virtio-net: driver features: %x\n",driver_features);
    virtio_net_reg_write32(VIRTIO_REG_DRIVER_FEATURES, driver_features);

    // tell device that feature negotiation is complete.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FEAT_OK);

      // re-read status to ensure FEATURES_OK is set.
    uint32_t status = virtio_net_reg_read32(VIRTIO_REG_DEVICE_STATUS);
    printf("virtio-net status is %x\n", status);

    if(!(status & VIRTIO_STATUS_FEAT_OK))
        PANIC("virtio net FEATURES_OK unset");

    net_vq_rx = init_net_virtq(0);
    net_vq_tx = init_net_virtq(1);
}

void virtio_net_init(void) {
    if (virtio_net_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976)
        PANIC("virtio-net: invalid magic value");
    if (virtio_net_reg_read32(VIRTIO_REG_VERSION) != 1)
        PANIC("virtio-net: invalid version");
    if (virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_NET)
        PANIC("virtio-net: invalid device id");

    // 1. Reset the device.
    virtio_net_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);
    // 2. Set the ACKNOWLEDGE status bit: the guest OS has noticed the device.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    // 3. Set the DRIVER status bit.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    // 4. Read device feature bits, and write the subset of feature bits understood by the OS and driver to the device.
    // NOT-IMPLEMENTED
    // 5. Set the FEATURES_OK status bit.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FEAT_OK);
    // 6. Re-read device status to ensure the FEATURES_OK bit is still set: otherwise, the device does not support our subset of features and the device is unusable.
    // NOT-IMPLEMENTED
    // 7. Perform device-specific setup, including discovery of virtqueues for the device
    virtq_net_init();


    // Get the read-only confi.
    net_configuration = (struct virtio_net_config *) (VIRTIO_REG_DEVICE_CONFIG + VIRTIO_NET_PADDR);

    // 8. Set the DRIVER_OK status bit.
    virtio_net_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);


    // Print Network Config
    printf("mac: %x:%x:%x:%x:%x:%x\n", net_configuration->mac[0], net_configuration->mac[1], net_configuration->mac[2],
         net_configuration->mac[3], net_configuration->mac[4], net_configuration->mac[5]);

    printf("virtio-net: status %x\n",net_configuration->status);
    printf("virtio-net: mtu %x\n",net_configuration->mtu);
    printf("virtio-net: max queues %x\n",net_configuration->max_virtqueue_pairs);


    //

    // Allocate a region to store requests to the device.
    // net_req_paddr = alloc_pages(align_up(sizeof(*net_req), PAGE_SIZE) / PAGE_SIZE);
    // net_req = (struct virtio_net_req *) net_req_paddr;
}

// Notifies the device that there is a new request. `desc_index` is the index
// of the head descriptor of the new request.
void virtq_net_kick(struct virtio_virtq *vq, int desc_index) {
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc_index;
    vq->avail.index++;
    __sync_synchronize();
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
    vq->last_used_index++;
}

void
virtio_net_send(uint8_t *buf, uint32_t len, int flag)
{

  int idx[2];
  idx[0] = (*net_vq_tx->used_index)++ % VIRTQ_ENTRY_NUM;
  idx[1] = (*net_vq_tx->used_index)++ % VIRTQ_ENTRY_NUM;

  fill_desc(&net_vq_tx->descs[idx[0]], (uint64_t)&net_rx_head[idx[0]], sizeof(struct virtio_net_hdr), VIRTQ_DESC_F_NEXT, idx[1]);

  fill_desc(&net_vq_tx->descs[idx[1]], (uint64_t)buf, len, flag, 0);

  // __sync_synchronize();

  // fill_avail(&net_vq_tx->avail, idx[0]);

  // __sync_synchronize();

  // virtio_net_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, 1);
  virtq_net_kick(net_vq_tx, idx[0]);

  while (virtq_is_busy(net_vq_tx))
    ;
  
}

void
virtio_net_recv()
{
  printf("Now in receive: %x\n",virtio_net_reg_read32(0x60));

  virtio_net_reg_write32(0x64,  virtio_net_reg_read32(0x60) & 0x3);

  __sync_synchronize();

  while(net_vq_rx->used.index == *net_vq_rx->used_index) {
    // printf("wait");
  }

  while(net_vq_rx->used.index != *net_vq_rx->used_index) {
    struct virtq_used_elem pkt = net_vq_rx->used.ring[*net_vq_rx->used_index % VIRTQ_ENTRY_NUM]; 

    uint8_t *data = net_rx_head[pkt.id].data; // + 10;
    size_t data_len = pkt.len - 10;

    // struct mbuf *m = mbuf_alloc();
    // char *tmp = mbuf_put(m, data_len);
    // if(tmp == 0) {
      // printf("error in get data: buf is too big!");
      // return;
    // }
    // fill_avail(&net_vq_rx->avail, pkt.id);

    // memmove(tmp, data, data_len);

    printf("receive %d bytes: ", data_len);
    for (int i = 0; i < data_len ; i++) {
        printf("%x ", data[i]);
    }
    printf("\n");

    (*net_vq_rx->used_index)++;


    __sync_synchronize();

    virtio_net_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, net_vq_rx->queue_index);
  }
}

// void
// virtio_net_intr(void)
// {
//   virtio_net_recv();
// }

void test_network() {
    uint8_t buf[42] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0xca, 0xfe, 0xf0, 0x0d, 0x01, 0x08, 0x06, 0x00, 0x01,
                    0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0xca, 0xfe, 0xf0, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x1c, 0x2b, 0xd8};
    virtio_net_send(buf, 42, 0);
    virtio_net_recv();
}