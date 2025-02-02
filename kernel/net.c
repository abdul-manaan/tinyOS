
#include "net.h"

struct virtio_virtq *net_vq_tx;
struct virtio_virtq *net_vq_rx;
paddr_t net_rx_h1_addr;
paddr_t net_rx_h2_addr;
struct virtio_net_hdr* net_rx_head1;
struct virtio_net_hdr* net_rx_head2;

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
      
      net_rx_h1_addr = alloc_pages(1);
      net_rx_h2_addr = alloc_pages(1);
      net_rx_head1 = (struct virtio_net_hdr*) net_rx_h1_addr;
      net_rx_head1 = (struct virtio_net_hdr*) net_rx_h2_addr;
      fill_desc(&vq->descs[0], (uint64_t)net_rx_h1_addr, sizeof(struct virtio_net_hdr), 2, 0);
      fill_desc(&vq->descs[1], (uint64_t)net_rx_h2_addr, sizeof(struct virtio_net_hdr), 2, 0);
      fill_avail(&vq->avail, 0);
      fill_avail(&vq->avail, 1);
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
    printf("net-dev: device id %d\n",virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID));
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

// void
// virtio_net_send(uint8_t *buf, uint32_t len, int flag)
// {

//   int idx[2];
//   idx[0] = (*net_vq_tx->used_index)++ % VIRTQ_ENTRY_NUM;
//   idx[1] = (*net_vq_tx->used_index)++ % VIRTQ_ENTRY_NUM;

//   fill_desc(&net_vq_tx->descs[idx[0]], (uint64_t)&, sizeof(struct virtio_net_hdr), VIRTQ_DESC_F_NEXT, idx[1]);

//   fill_desc(&net_vq_tx->descs[idx[1]], (uint64_t)buf, len, flag, 0);

//   virtq_net_kick(net_vq_tx, idx[0]);

//   while (virtq_is_busy(net_vq_tx))
//     ;
  
// }

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


    uint8_t *data = net_rx_head1->data; // + 10;
    printf("data-recv: %x\n",data[0]);
    printf("data-recv: %x\n",data[1]);
    printf("data-recv: %x\n",data[2]);
    printf("data-recv: %x\n",data[3]);
    size_t data_len = pkt.len - 10;

    printf("received: id is %d\n",pkt.id);
    printf("received: len is %d\n",pkt.len);

    printf("received: d.addr is %x \n", net_vq_rx->descs[pkt.id].addr);
    printf("received: d.len is %d \n", net_vq_rx->descs[pkt.id].len);
    printf("received: d.flags is %x \n", net_vq_rx->descs[pkt.id].flags);
    printf("received: d.next is %x \n", net_vq_rx->descs[pkt.id].next);
    if (data_len > DATA_LEN) {
      PANIC("virtio-net: Data-length is wrong %d\n",data_len);
    }

    // struct mbuf *m = mbuf_alloc();
    // char *tmp = mbuf_put(m, data_len);
    // if(tmp == 0) {
      // printf("error in get data: buf is too big!");
      // return;
    // }
    // fill_avail(&net_vq_rx->avail, pkt.id);

    // memmove(tmp, data, data_len);

    printf("receive %d bytes: ", data_len);
    for (size_t i = 0; i < data_len ; i++) {
        printf("%x ", data[i]);
    }
    printf("\n");

    (*net_vq_rx->used_index)++;


    __sync_synchronize();

    virtio_net_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, net_vq_rx->queue_index);
  }
}

// ARP constants
#define ARP_REQUEST 1
#define ETH_TYPE_ARP 0x0806
#define HW_TYPE_ETHERNET 1
#define PROTO_TYPE_IPV4 0x0800
#define MAC_ADDR_LEN 6
#define IPV4_ADDR_LEN 4
// Ethernet and ARP packet structures
struct eth_header {
    uint8_t dest[6];
    uint8_t src[MAC_ADDR_LEN];
    uint16_t eth_type;
} __attribute__((packed));

struct arp_packet {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    uint8_t sender_mac[MAC_ADDR_LEN];
    uint8_t sender_ip[IPV4_ADDR_LEN];
    uint8_t target_mac[MAC_ADDR_LEN];
    uint8_t target_ip[IPV4_ADDR_LEN];
} __attribute__((packed));

// void
// virtio_net_intr(void)
// {
//   virtio_net_recv();
// }

void test_network() {
    //Test: ARP Request

    // Allocate space for request

    paddr_t netPacket = alloc_pages(1);

    struct virtio_net_hdr * netPk = (struct virtio_net_hdr*) netPacket;

    netPk->gso_type = VIRTIO_NET_HDR_GSO_NONE;

    netPk->flags = 0;


    struct eth_header *eth = (struct eth_header *)(netPacket + offsetof(struct virtio_net_hdr, data));
    struct arp_packet *arp = (struct arp_packet *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header));

    // Fill Ethernet header
    memset(eth->dest, 0xFF, MAC_ADDR_LEN);  // Broadcast
    eth->src[0] = 0x52;
    eth->src[1] = 0x54;
    eth->src[2] = 0x00;
    eth->src[3] = 0x12;
    eth->src[4] = 0x34;
    eth->src[5] = 0x56;
    // memset(eth->src, 0xAA, MAC_ADDR_LEN);   // Placeholder MAC address
    eth->eth_type = 0x0608;  // ARP type (little-endian for RISC-V)

    // Fill ARP request
    arp->hw_type = 0x0100;  // Ethernet (little-endian)
    arp->proto_type = 0x0008;  // IPv4 (little-endian)
    arp->hw_size = MAC_ADDR_LEN;
    arp->proto_size = IPV4_ADDR_LEN;
    arp->opcode = 0x0100;  // ARP Request (little-endian)
    memcpy(arp->sender_mac, eth->src, MAC_ADDR_LEN);  // Sender MAC
    memcpy(arp->sender_ip, "\x0A\x00\x02\x00", IPV4_ADDR_LEN);  // 10.0.2.0
    memset(arp->target_mac, 0x00, MAC_ADDR_LEN);  // Target MAC unknown
    memcpy(arp->target_ip, "\x0A\x00\x00\x04", IPV4_ADDR_LEN);  // 192.168.0.2

    // Step 4: Add the packet to the descriptor table
    // Construct the virtqueue descriptors (using 3 descriptors).
    struct virtio_virtq *vq = net_vq_tx;
    vq->descs[0].addr = netPacket;
    vq->descs[0].len = sizeof(uint32_t) * 2 + sizeof(uint16_t)*5 + sizeof(struct arp_packet) + sizeof(struct eth_header);
    vq->descs[0].flags = VIRTQ_DESC_F_USED;
    vq->descs[0].next = 1;

    // vq->descs[1].addr = netPacket + offsetof(struct virtio_net_hdr, data);
    // vq->descs[1].len = sizeof(struct arp_packet) + sizeof(struct eth_header);
    // vq->descs[1].flags = 0;
    // vq->descs[1].next = 2;

    // Notify the device that there is a new request.
    virtq_net_kick(vq, 0);

    // virtio_net_reg_write32(0x20, 0);  // Notify device (queue 0)

    // Wait until the device finishes processing.
    while (virtq_is_busy(net_vq_rx))
        ;

    // virtio-blk: If a non-zero value is returned, it's an error.
    // while (netPk->num_buffers != 1)
    //   ;


    // Step 5: Notify the device

    printf("ARP request sent.\n");

    virtio_net_recv();
}


// Structure of a DNS header
struct DNSHeader {
    uint16_t id;       // Identification
    uint16_t flags;    // Query/Response flags
    uint16_t qdcount;  // Number of questions
    uint16_t ancount;  // Number of answers
    uint16_t nscount;  // Number of authority records
    uint16_t arcount;  // Number of additional records
};

// Structure of a DNS question footer
struct QuestionFooter {
    uint16_t qtype;
    uint16_t qclass;
};


struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;      // IP header length
    unsigned int version:4;  // IP version (4 for IPv4)
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    uint8_t tos;             // Type of service
    uint16_t tot_len;        // Total length (header + data)
    uint16_t id;             // Identification
    uint16_t frag_off;       // Fragment offset
    uint8_t ttl;             // Time to Live
    uint8_t protocol;        // Protocol (e.g., 17 for UDP)
    uint16_t check;          // Header checksum
    uint32_t saddr;          // Source IP address
    uint32_t daddr;          // Destination IP address
};

struct udphdr {
    uint16_t source;   // Source port
    uint16_t dest;     // Destination port
    uint16_t len;      // Length (header + data)
    uint16_t check;    // Checksum (optional)
};

#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define BUFFER_SIZE 512
#define DEST_MAC "\x08\x7e\x64\x06\x17\x18" // Example destination MAC address
#define SRC_MAC "\x08\x00\x27\x65\x43\x21"  // Example source MAC address
#define DEST_IP "75.75.75.75"
#define SRC_IP "2.0.0.10"
#define DEST_PORT 53
#define SRC_PORT 12345

#define ETH_P_IP 0x0800

#define IPPROTO_UDP 17

uint16_t htons(uint16_t hostshort) {
    // Check system endianness
    uint16_t test = 1;
    if (*(uint8_t *)&test == 1) {
        // Little-endian: swap bytes
        return (hostshort >> 8) | (hostshort << 8);
    } else {
        // Big-endian: return as-is
        return hostshort;
    }
}

// Function to format domain name for DNS query
void format_dns_name(unsigned char *dns, const char *host) {
    int lock = 0;
    strcat((char *)dns, ".");
    for (size_t i = 0; i < strlen(host); i++) {
        if (host[i] == '.') {
            *dns = i - lock;
            dns++;
            memcpy(dns, host + lock, i - lock);
            dns += i - lock;
            lock = i + 1;
        }
    }
    *dns = strlen(host) - lock;
    dns++;
    memcpy(dns, host + lock, strlen(host) - lock);
    dns += strlen(host) - lock;
    *dns = 0; // Null terminator
}

uint32_t inet_addr(const char *ip) {
    uint32_t result = 0;
    uint8_t octet;
    int shift = 24;  // Start from the highest byte (big-endian)
    
    while (*ip) {
        octet = 0;
        
        // Convert each octet
        while (*ip >= '0' && *ip <= '9') {
            octet = octet * 10 + (*ip - '0');
            ip++;
        }
        
        // Place the octet in the correct position
        result |= (octet << shift);
        shift -= 8;
        
        // If there's no dot, break (end of string)
        if (*ip == '.') {
            ip++;  // Move past the dot
        } else {
            break;
        }
    }
    
    return result;
}


void test_dns() {

   // Allocate space for request
    paddr_t netPacket = alloc_pages(1);
    struct virtio_net_hdr * netPk = (struct virtio_net_hdr*) netPacket;
    netPk->gso_type = VIRTIO_NET_HDR_GSO_NONE;
    netPk->flags = 0;


    struct eth_header *eth = (struct eth_header *)(netPacket + offsetof(struct virtio_net_hdr, data));
    struct iphdr *ip = (struct iphdr *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header));
    struct udphdr *udp = (struct udphdr *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header) + sizeof(struct iphdr));
    struct DNSHeader *dns = (struct DNSHeader *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
    unsigned char *qname = (unsigned char *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader));
    
    // Ethernet Header
    // Fill Ethernet header
    memcpy(eth->dest, DEST_MAC, MAC_ADDR_LEN);  // Broadcast
    eth->src[0] = 0x52;
    eth->src[1] = 0x54;
    eth->src[2] = 0x00;
    eth->src[3] = 0x12;
    eth->src[4] = 0x34;
    eth->src[5] = 0x56;
    eth->eth_type = htons(ETH_P_IP);

    // IP Header
    // struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader) + strlen("example.com") + 2 + sizeof(struct QuestionFooter));
    ip->id = htons(1234);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(SRC_IP);
    ip->daddr = inet_addr(DEST_IP);

    printf("IP Len: %x\n",sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader) + strlen("example.com") + 2 + sizeof(struct QuestionFooter));
    printf("IP Len: %x\n",htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader) + strlen("example.com") + 2 + sizeof(struct QuestionFooter)));
    // ip->check = checksum(ip, sizeof(struct iphdr));

    // UDP Header
    udp->source = htons(SRC_PORT);
    udp->dest = htons(DEST_PORT);
    udp->len = htons(sizeof(struct udphdr) + sizeof(struct DNSHeader) + strlen("example.com") + 2 + sizeof(struct QuestionFooter));
    udp->check = 0; // UDP checksum is optional

    // DNS Header
    dns->id = htons(0x4321);
    dns->flags = htons(0x0100);
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    // DNS Query
    format_dns_name(qname, "example.com");

    struct QuestionFooter *qfooter = (struct QuestionFooter *)(qname + strlen((const char *)qname) + 1);
    qfooter->qtype = htons(1);
    qfooter->qclass = htons(1);

    // Send Packet
 // Step 4: Add the packet to the descriptor table
    // Construct the virtqueue descriptors (using 3 descriptors).
    struct virtio_virtq *vq = net_vq_tx;
    vq->descs[0].addr = netPacket;
    vq->descs[0].len = sizeof(uint8_t) * 1 + sizeof(uint16_t)*5 + sizeof(struct arp_packet) + sizeof(struct eth_header) +  sizeof(struct eth_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader) + 11;

    vq->descs[0].flags = VIRTQ_DESC_F_USED;
    vq->descs[0].next = 1;

    // vq->descs[1].addr = netPacket + offsetof(struct virtio_net_hdr, data);
    // vq->descs[1].len = sizeof(struct arp_packet) + sizeof(struct eth_header);
    // vq->descs[1].flags = 0;
    // vq->descs[1].next = 2;

    // Notify the device that there is a new request.
    virtq_net_kick(vq, 0);

    // virtio_net_reg_write32(0x20, 0);  // Notify device (queue 0)

    // Wait until the device finishes processing.
    while (virtq_is_busy(net_vq_rx))
        ;

    // virtio-blk: If a non-zero value is returned, it's an error.
    // while (netPk->num_buffers != 1)
    //   ;


    // Step 5: Notify the device

    printf("DNS request sent.\n");

    // virtio_net_recv();

}