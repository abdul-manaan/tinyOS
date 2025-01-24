#pragma once

#include "kernel.h"
#include "constants.h"
#include "virt.h"

#define VIRTIO_NET_S_LINK_UP     1 
#define VIRTIO_NET_S_ANNOUNCE    2

#define VIRTIO_NET_F_MTU 4
#define VIRTIO_NET_F_MAC 16
#define VIRTIO_NET_F_CSUM 1
#define ETHADDR_LEN 6

#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1
#define VIRTIO_NET_HDR_F_DATA_VALID 2
#define VIRTIO_NET_HDR_F_RSC_INFO 4
#define VIRTIO_NET_HDR_GSO_NONE 0
#define VIRTIO_NET_HDR_GSO_TCPV4 1
#define VIRTIO_NET_HDR_GSO_UDP 3
#define VIRTIO_NET_HDR_GSO_TCPV6 4
#define VIRTIO_NET_HDR_GSO_UDP_L4 5
#define VIRTIO_NET_HDR_GSO_ECN 0x80


#define DATA_LEN 1514
struct virtio_net_hdr {
  uint8_t flags;
  uint8_t gso_type;
  uint16_t hdr_len;
  uint16_t gso_size;
  uint16_t csum_start;
  uint16_t csum_offset;
  uint8_t data[DATA_LEN];
} __attribute__((packed));

struct virtio_net_rx_hdr {
  uint8_t flags;
  uint8_t gso_type;
  uint16_t hdr_len;
  uint16_t gso_size;
  uint16_t csum_start;
  uint16_t csum_offset;
  uint8_t data[512];
} __attribute__((packed));

struct virtio_net_config {
  uint8_t mac[6];
  uint16_t status;
// #if defined(VIRTIO_NET_F_MQ)
  uint16_t max_virtqueue_pairs;
// #endif // VIRTIO_NET_F_MQ
  uint16_t mtu;
} __attribute__((packed));

extern void virtio_net_init(void) ;

extern void test_network(void);