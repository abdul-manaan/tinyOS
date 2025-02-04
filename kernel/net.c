/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 2025-01-21--18:26:52
 * Last modified: 2025-02-03--19:07:19
 * All rights reserved.
 */


/*
 * net.c
 *
 * This file contains the implementation for the virtio network device driver.
 * It sets up virtqueues for transmit (tx) and receive (rx) operations, provides
 * helper functions to read/write device registers, builds descriptors for packet
 * transfers, and constructs example Ethernet, ARP, and DNS packets.
 *
 * The code is organized as follows:
 *  - Global variables: pointers to virtqueues, configuration data, etc.
 *  - Register access functions: to read/write 32- and 64-bit registers.
 *  - Descriptor helper functions: to fill in virtqueue descriptor and available ring entries.
 *  - Initialization functions: set up the virtqueues and negotiate device features.
 *  - Packet operations: functions to send and receive network packets.
 *  - Test functions: test_network() and test_dns() build and send sample ARP and DNS packets.
 */

#include "net.h"

/* Global pointers and configuration for the virtio network device */
struct virtio_virtq *net_vq_tx;      // Transmit virtqueue pointer
struct virtio_virtq *net_vq_rx;      // Receive virtqueue pointer
paddr_t net_rx_h1_addr;              // Physical address for first rx header
paddr_t net_rx_h2_addr;              // Physical address for second rx header
struct virtio_net_hdr* net_rx_head1; // Pointer to first rx header structure
struct virtio_net_hdr* net_rx_head2; // Pointer to second rx header structure

struct virtio_net_config *net_configuration; // Pointer to device configuration structure
paddr_t net_req_paddr;              // Physical address allocated for network requests
unsigned net_capacity;              // Capacity (unused in this snippet)

#define NUM_QUEUES 2              // Number of virtqueues for the device

/*
 * virtio_net_reg_read32
 *
 * Reads a 32-bit register from the virtio network device.
 *
 * Input:
 *   offset - Offset (in bytes) from the base address (VIRTIO_NET_PADDR)
 *
 * Output:
 *   Returns the 32-bit value read from the register.
 */
uint32_t virtio_net_reg_read32(unsigned offset) {
    return *((volatile uint32_t *) (VIRTIO_NET_PADDR + offset));
}

/*
 * virtio_net_reg_read64
 *
 * Reads a 64-bit register from the virtio network device.
 *
 * Input:
 *   offset - Offset (in bytes) from the base address (VIRTIO_NET_PADDR)
 *
 * Output:
 *   Returns the 64-bit value read from the register.
 */
uint64_t virtio_net_reg_read64(unsigned offset) {
    return *((volatile uint64_t *) (VIRTIO_NET_PADDR + offset));
}

/*
 * virtio_net_reg_write32
 *
 * Writes a 32-bit value to a device register.
 *
 * Input:
 *   offset - Register offset (in bytes) from VIRTIO_NET_PADDR
 *   value  - The 32-bit value to write
 *
 * Output:
 *   The register is updated with the given value.
 */
void virtio_net_reg_write32(unsigned offset, uint32_t value) {
    *((volatile uint32_t *) (VIRTIO_NET_PADDR + offset)) = value;
}

/*
 * virtio_net_reg_fetch_and_or32
 *
 * Reads a 32-bit register, OR's it with the given value, and writes it back.
 *
 * Input:
 *   offset - Register offset from VIRTIO_NET_PADDR
 *   value  - The value to OR with the current register value.
 *
 * Output:
 *   The register is updated with (old value | value).
 */
void virtio_net_reg_fetch_and_or32(unsigned offset, uint32_t value) {
    virtio_net_reg_write32(offset, virtio_net_reg_read32(offset) | value);
}

/*
 * fill_desc
 *
 * Fills a virtqueue descriptor with the specified parameters.
 *
 * Input:
 *   desc  - Pointer to the descriptor structure.
 *   addr  - Physical address of the buffer.
 *   len   - Length of the buffer.
 *   flags - Descriptor flags (e.g., indicating next descriptor or device writable).
 *   next  - Index of the next descriptor.
 *
 * Process:
 *   The function casts the pointer to volatile to enforce proper memory ordering.
 *   It then writes the fields and uses a memory barrier (__sync_synchronize)
 *   to prevent reordering.
 */
static inline void fill_desc(struct virtq_desc *desc, uint64_t addr,
                             uint32_t len, uint16_t flags, uint16_t next)
{
    // Cast pointer to volatile to ensure proper ordering of memory accesses.
    volatile struct virtq_desc *pt = (volatile struct virtq_desc *)desc;
    pt->addr = addr;
    pt->len = len;
    pt->flags = flags;
    pt->next = next;
    __sync_synchronize();
}

/*
 * fill_avail
 *
 * Fills an entry in the available ring of a virtqueue.
 *
 * Input:
 *   avail - Pointer to the available ring structure.
 *   idx   - Index of the descriptor that is now available.
 *
 * Process:
 *   Places the descriptor index into the ring, increments the index,
 *   and then enforces memory ordering.
 */
static inline void fill_avail(struct virtq_avail *avail, uint16_t idx)
{
    volatile struct virtq_avail *pt = (volatile struct virtq_avail *)avail;
    pt->ring[avail->index % VIRTQ_ENTRY_NUM] = idx;
    pt->index++;
    __sync_synchronize();
}

/*
 * init_net_virtq
 *
 * Initializes one of the virtio network device's virtqueues.
 *
 * Input:
 *   index - Virtqueue index (0 for receive, 1 for transmit)
 *
 * Process:
 *   - Allocates physical pages for the virtqueue structure.
 *   - Configures the virtqueue by writing to device registers.
 *   - For the first queue (rx), additional headers are allocated and descriptors are filled.
 *
 * Output:
 *   Returns a pointer to the initialized virtqueue.
 */
struct virtio_virtq *init_net_virtq(unsigned index) {
    // Allocate physical memory for the virtqueue structure.
    paddr_t virtq_paddr = alloc_pages(align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    struct virtio_virtq *vq = (struct virtio_virtq *) virtq_paddr;
    vq->queue_index = index;
    vq->used_index = (volatile uint16_t *) &vq->used.index;

    // Select the queue and check that it's not already ready.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_SEL, index);
    printf("1. queue %d STATUS: %d\n", index, virtio_net_reg_read32(VIRTIO_REG_QUEUE_READY));

    if (virtio_net_reg_read32(VIRTIO_REG_QUEUE_READY))
        PANIC("virtio net should not be ready");

    // Read the maximum queue size.
    uint32_t max = virtio_net_reg_read32(VIRTIO_REG_QUEUE_NUM_MAX);
    if (max == 0)
        PANIC("virtio net has no queue");
    if (max < NUM_QUEUES)
        PANIC("virtio net max queue too short");

    // Set queue size.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);

    // Set queue alignment.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_ALIGN, 0);
    // Set the physical address of the queue.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_PFN, virtq_paddr);

    // For the first queue (queue index 0 is typically for receive):
    if (index == 0) {
        // Allocate physical pages for two network receive headers.
        net_rx_h1_addr = alloc_pages(1);
        net_rx_h2_addr = alloc_pages(1);
        net_rx_head1 = (struct virtio_net_hdr*) net_rx_h1_addr;
        net_rx_head2 = (struct virtio_net_hdr*) net_rx_h2_addr;
        // Fill descriptors for the receive virtqueue.
        fill_desc(&vq->descs[0], (uint64_t)net_rx_h1_addr, sizeof(struct virtio_net_hdr), 2, 0);
        fill_desc(&vq->descs[1], (uint64_t)net_rx_h2_addr, sizeof(struct virtio_net_hdr), 2, 0);
        fill_avail(&vq->avail, 0);
        fill_avail(&vq->avail, 1);
    }
    // Write physical addresses of the descriptor table, available ring, and used ring.
    virtio_net_reg_write32(VIRTQ_MMIO_DESC, (uint32_t)vq->descs);
    virtio_net_reg_write32(VIRTQ_DRIVER_DESC, (uint32_t)&vq->avail);
    virtio_net_reg_write32(VIRTQ_DEVICE_DESC, (uint32_t)&vq->used);

    // Mark the queue as ready.
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_READY, 0x1);
    printf("2. queue %d STATUS: %d\n", index, virtio_net_reg_read32(VIRTIO_REG_QUEUE_READY));

    return vq;
}

/*
 * virtq_net_init
 *
 * Initializes the virtqueues for the network device.
 *
 * Process:
 *   - Prints device IDs for debugging.
 *   - Checks device magic, version, and resets the device.
 *   - Sets up device status and negotiates features.
 *   - Calls init_net_virtq for both the receive and transmit queues.
 */
void virtq_net_init() {
    // Print device identification registers.
    printf("VIRTIO_REG_DEVICE_ID: %x\n", virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID));
    printf("VIRTIO_REG_VENDOR_ID: %x\n", virtio_net_reg_read32(VIRTIO_REG_VENDOR_ID));

    // Verify the magic, version, device id, and vendor id.
    if (virtio_net_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976 ||
        virtio_net_reg_read32(VIRTIO_REG_VERSION) != 1 ||
        virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_NET ||
        virtio_net_reg_read32(VIRTIO_REG_VENDOR_ID) != 0x554d4551) {
        PANIC("could not find virtio net");
    }

    // Reset the device.
    virtio_net_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);

    // Set the ACKNOWLEDGE status bit.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);

    // Set the DRIVER status bit.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);

    // Negotiate features with the device.
    uint32_t device_features = virtio_net_reg_read32(VIRTIO_REG_DEVICE_FEATURES);
    printf("virtio-net: device feature is %x\n", device_features);
    uint32_t driver_features = (1 << VIRTIO_NET_F_MTU) | (1 << VIRTIO_NET_F_MAC) | (1 << VIRTIO_NET_F_CSUM);
    printf("virtio-net: driver features: %x\n", driver_features);
    virtio_net_reg_write32(VIRTIO_REG_DRIVER_FEATURES, driver_features);

    // Signal that feature negotiation is complete.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FEAT_OK);

    // Verify that the FEATURES_OK bit is set.
    uint32_t status = virtio_net_reg_read32(VIRTIO_REG_DEVICE_STATUS);
    printf("virtio-net status is %x\n", status);
    if (!(status & VIRTIO_STATUS_FEAT_OK))
        PANIC("virtio net FEATURES_OK unset");

    // Initialize the receive and transmit virtqueues.
    net_vq_rx = init_net_virtq(0);
    net_vq_tx = init_net_virtq(1);
}

/*
 * virtio_net_init
 *
 * Top-level initialization function for the virtio network device.
 *
 * Process:
 *   - Verifies device registers.
 *   - Resets the device and sets initial status bits.
 *   - Calls virtq_net_init to set up virtqueues.
 *   - Retrieves the network configuration.
 *   - Marks the device as ready for use.
 */
void virtio_net_init(void) {
    if (virtio_net_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976)
        PANIC("virtio-net: invalid magic value");
    if (virtio_net_reg_read32(VIRTIO_REG_VERSION) != 1)
        PANIC("virtio-net: invalid version");
    printf("net-dev: device id %d\n", virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID));
    if (virtio_net_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_NET)
        PANIC("virtio-net: invalid device id");

    // Reset the device.
    virtio_net_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);
    // Set the ACKNOWLEDGE and DRIVER status bits.
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    virtio_net_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    // Feature negotiation (not fully implemented here).
    // Set up virtqueues.
    virtq_net_init();

    // Obtain a pointer to the device configuration.
    net_configuration = (struct virtio_net_config *) (VIRTIO_REG_DEVICE_CONFIG + VIRTIO_NET_PADDR);

    // Mark the device as ready.
    virtio_net_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

    // Print network configuration (MAC, status, MTU, max queues).
    printf("mac: %x:%x:%x:%x:%x:%x\n", net_configuration->mac[0], net_configuration->mac[1],
           net_configuration->mac[2], net_configuration->mac[3], net_configuration->mac[4], net_configuration->mac[5]);
    printf("virtio-net: status %x\n", net_configuration->status);
    printf("virtio-net: mtu %x\n", net_configuration->mtu);
    printf("virtio-net: max queues %x\n", net_configuration->max_virtqueue_pairs);

    // Allocate request region if needed.
    // net_req_paddr = alloc_pages(align_up(sizeof(*net_req), PAGE_SIZE) / PAGE_SIZE);
    // net_req = (struct virtio_net_req *) net_req_paddr;
}

/*
 * virtq_net_kick
 *
 * Notifies the device that a new request is ready in the virtqueue.
 *
 * Input:
 *   vq         - Pointer to the virtqueue structure.
 *   desc_index - The index of the head descriptor for the new request.
 *
 * Process:
 *   - Inserts the descriptor index into the available ring.
 *   - Increments the available index and ensures memory ordering.
 *   - Writes to the device's queue notify register.
 *   - Increments the last used index.
 */
void virtq_net_kick(struct virtio_virtq *vq, int desc_index) {
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc_index;
    vq->avail.index++;
    __sync_synchronize();
    virtio_net_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
    vq->last_used_index++;
}

/*
 * virtio_net_recv
 *
 * Handles receiving packets from the network device.
 *
 * Process:
 *   - Reads the device status.
 *   - Clears certain bits in a register.
 *   - Waits until new packets are available in the used ring.
 *   - Processes each used descriptor, prints packet details, and notifies the device.
 *
 * Note:
 *   This example prints out details of the received packet and uses the
 *   network receive header (net_rx_head1). Data is expected to be in the
 *   descriptor's associated buffer.
 */
void virtio_net_recv() {
    printf("Now in receive: %x\n", virtio_net_reg_read32(0x60));

    // Clear bits in register 0x64 based on the current register at 0x60.
    virtio_net_reg_write32(0x64, virtio_net_reg_read32(0x60) & 0x3);
    __sync_synchronize();

    // Wait until a packet has been received.
    while (net_vq_rx->used.index == *net_vq_rx->used_index)
        ; // Busy-wait (could be improved with proper blocking)

    // Process all received packets.
    while (net_vq_rx->used.index != *net_vq_rx->used_index) {
        struct virtq_used_elem pkt = net_vq_rx->used.ring[*net_vq_rx->used_index % VIRTQ_ENTRY_NUM];

        // Retrieve packet data from the receive header.
        uint8_t *data = net_rx_head1->data;
        printf("data-recv: %x\n", data[0]);
        printf("data-recv: %x\n", data[1]);
        printf("data-recv: %x\n", data[2]);
        printf("data-recv: %x\n", data[3]);
        size_t data_len = pkt.len - 10;

        printf("received: id is %d\n", pkt.id);
        printf("received: len is %d\n", pkt.len);
        printf("received: d.addr is %x \n", net_vq_rx->descs[pkt.id].addr);
        printf("received: d.len is %d \n", net_vq_rx->descs[pkt.id].len);
        printf("received: d.flags is %x \n", net_vq_rx->descs[pkt.id].flags);
        printf("received: d.next is %x \n", net_vq_rx->descs[pkt.id].next);
        if (data_len > DATA_LEN)
            PANIC("virtio-net: Data-length is wrong %d\n", data_len);

        printf("receive %d bytes: ", data_len);
        for (size_t i = 0; i < data_len; i++) {
            printf("%x ", data[i]);
        }
        printf("\n");

        (*net_vq_rx->used_index)++;
        __sync_synchronize();
        virtio_net_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, net_vq_rx->queue_index);
    }
}

/*
 * Structures for Ethernet and ARP packets.
 * These are used to construct and parse Ethernet and ARP messages.
 */
struct eth_header {
    uint8_t dest[6];              // Destination MAC address
    uint8_t src[MAC_ADDR_LEN];    // Source MAC address
    uint16_t eth_type;            // Ethernet type field
} __attribute__((packed));

struct arp_packet {
    uint16_t hw_type;             // Hardware type (e.g., Ethernet)
    uint16_t proto_type;          // Protocol type (e.g., IPv4)
    uint8_t hw_size;              // Hardware address length
    uint8_t proto_size;           // Protocol address length
    uint16_t opcode;              // Operation code (request/reply)
    uint8_t sender_mac[MAC_ADDR_LEN]; // Sender MAC address
    uint8_t sender_ip[IPV4_ADDR_LEN];   // Sender IP address
    uint8_t target_mac[MAC_ADDR_LEN];   // Target MAC address
    uint8_t target_ip[IPV4_ADDR_LEN];     // Target IP address
} __attribute__((packed));


/*
 * DNS and UDP/IP related structures.
 * These structures are used to construct a DNS query packet.
 */
struct DNSHeader {
    uint16_t id;       // Identification
    uint16_t flags;    // Flags for query/response
    uint16_t qdcount;  // Number of questions
    uint16_t ancount;  // Number of answers
    uint16_t nscount;  // Number of authority records
    uint16_t arcount;  // Number of additional records
};

struct QuestionFooter {
    uint16_t qtype;    // Query type
    uint16_t qclass;   // Query class
};

struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;      // Header length
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
    uint16_t len;      // UDP header and data length
    uint16_t check;    // Checksum (optional)
};

/* DNS and network constants */
#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define BUFFER_SIZE 512
#define DEST_MAC "\x08\x7e\x64\x06\x17\x18" // Example destination MAC
#define SRC_MAC "\x08\x00\x27\x65\x43\x21"  // Example source MAC
#define DEST_IP "75.75.75.75"
#define SRC_IP "2.0.0.10"
#define DEST_PORT 53
#define SRC_PORT 12345

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

/*
 * htons
 *
 * Converts a 16-bit value from host byte order to network byte order.
 *
 * Input:
 *   hostshort - 16-bit number in host byte order.
 *
 * Output:
 *   The value in network byte order (big-endian).
 */
uint16_t htons(uint16_t hostshort) {
    uint16_t test = 1;
    if (*(uint8_t *)&test == 1) {
        // System is little-endian; swap bytes.
        return (hostshort >> 8) | (hostshort << 8);
    } else {
        // Big-endian; no change.
        return hostshort;
    }
}

/*
 * format_dns_name
 *
 * Formats a domain name into DNS query format.
 *
 * Input:
 *   dns  - Buffer where the formatted name will be written.
 *   host - The human-readable domain name (e.g., "example.com")
 *
 * Process:
 *   The function converts the domain name into the DNS label format by inserting
 *   length bytes before each label and terminating with a zero byte.
 */
void format_dns_name(unsigned char *dns, const char *host) {
    int lock = 0;
    strcat((char *)dns, "."); // Append a dot for easier parsing.
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
    *dns = 0; // Null terminator for the DNS name.
}

/*
 * inet_addr
 *
 * Converts an IPv4 address in dotted-decimal notation into a 32-bit number.
 *
 * Input:
 *   ip - String containing the IP address (e.g., "192.168.0.1")
 *
 * Output:
 *   32-bit integer representation of the IP address in network byte order.
 */
uint32_t inet_addr(const char *ip) {
    uint32_t result = 0;
    uint8_t octet;
    int shift = 24;  // Start from the highest byte (big-endian)
    
    while (*ip) {
        octet = 0;
        // Convert each octet from characters to number.
        while (*ip >= '0' && *ip <= '9') {
            octet = octet * 10 + (*ip - '0');
            ip++;
        }
        // Shift the octet into its proper position.
        result |= (octet << shift);
        shift -= 8;
        if (*ip == '.') {
            ip++;  // Skip the dot.
        } else {
            break;
        }
    }
    return result;
}

/*
 * test_dns
 *
 * Constructs and sends a DNS query packet as a test.
 *
 * Process:
 *   - Allocates space for a network packet.
 *   - Builds Ethernet, IP, UDP, and DNS headers.
 *   - Formats the DNS query for the domain "example.com".
 *   - Fills a virtqueue descriptor with the packet information.
 *   - Notifies the device and waits for processing.
 *   - Prints status messages to indicate that the DNS request was sent.
 */
void test_dns() {
    // Allocate physical memory for the network packet.
    paddr_t netPacket = alloc_pages(1);
    struct virtio_net_hdr *netPk = (struct virtio_net_hdr*) netPacket;
    netPk->gso_type = VIRTIO_NET_HDR_GSO_NONE;
    netPk->flags = 0;

    // Calculate pointers to various protocol headers within the packet.
    struct eth_header *eth = (struct eth_header *)(netPacket + offsetof(struct virtio_net_hdr, data));
    struct iphdr *ip = (struct iphdr *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header));
    struct udphdr *udp = (struct udphdr *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header) + sizeof(struct iphdr));
    struct DNSHeader *dns = (struct DNSHeader *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
    unsigned char *qname = (unsigned char *)(netPacket + offsetof(struct virtio_net_hdr, data) + sizeof(struct eth_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader));

    // ------------------ Ethernet Header ------------------
    // Fill Ethernet header with destination MAC, source MAC, and type.
    memcpy(eth->dest, DEST_MAC, MAC_ADDR_LEN); // Set destination MAC.
    eth->src[0] = 0x52;
    eth->src[1] = 0x54;
    eth->src[2] = 0x00;
    eth->src[3] = 0x12;
    eth->src[4] = 0x34;
    eth->src[5] = 0x56;
    eth->eth_type = htons(ETH_P_IP);  // Set Ethernet type to IP.

    // ------------------ IP Header ------------------
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    // Total length includes IP header, UDP header, DNS header, and query.
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) +
                        sizeof(struct DNSHeader) + strlen("example.com") + 2 + sizeof(struct QuestionFooter));
    ip->id = htons(1234);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(SRC_IP);
    ip->daddr = inet_addr(DEST_IP);
    // ip->check = checksum(ip, sizeof(struct iphdr)); // Checksum computation (omitted)

    // Debug printouts for IP length.
    printf("IP Len: %x\n", sizeof(struct iphdr) + sizeof(struct udphdr) +
                             sizeof(struct DNSHeader) + strlen("example.com") + 2 + sizeof(struct QuestionFooter));
    printf("IP Len: %x\n", ip->tot_len);

    // ------------------ UDP Header ------------------
    udp->source = htons(SRC_PORT);
    udp->dest = htons(DEST_PORT);
    udp->len = htons(sizeof(struct udphdr) + sizeof(struct DNSHeader) +
                     strlen("example.com") + 2 + sizeof(struct QuestionFooter));
    udp->check = 0; // UDP checksum is optional.

    // ------------------ DNS Header ------------------
    dns->id = htons(0x4321);
    dns->flags = htons(0x0100); // Standard query.
    dns->qdcount = htons(1);    // One question.
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    // ------------------ DNS Query ------------------
    // Format the DNS query name (e.g., "example.com") into proper format.
    format_dns_name(qname, "example.com");
    // Position the QuestionFooter immediately after the query name.
    struct QuestionFooter *qfooter = (struct QuestionFooter *)(qname + strlen((const char *)qname) + 1);
    qfooter->qtype = htons(1);   // Query type A (host address).
    qfooter->qclass = htons(1);  // Query class IN (Internet).

    // ------------------ Packet Transmission ------------------
    // Fill in the virtqueue descriptor for transmission.
    struct virtio_virtq *vq = net_vq_tx;
    vq->descs[0].addr = netPacket;
    vq->descs[0].len = sizeof(uint8_t) * 1 + sizeof(uint16_t) * 5 + sizeof(struct eth_header) +
                       sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader) +
                       strlen("example.com") + 2 + sizeof(struct QuestionFooter);
    vq->descs[0].flags = VIRTQ_DESC_F_USED;
    vq->descs[0].next = 1;

    // Notify the device that a new DNS request is ready.
    virtq_net_kick(vq, 0);

    // Wait until the device finishes processing the packet.
    while (virtq_is_busy(net_vq_rx))
        ;

    printf("DNS request sent.\n");

    // Optionally, invoke the receive function to process a response.
    // virtio_net_recv();
}