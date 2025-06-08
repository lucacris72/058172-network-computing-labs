#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

/* This is the data record stored in the map */
/* TODO 9: Define map and structure to hold packet and byte counters */
struct datarec {
   __u64 rx_packets;
   __u64 rx_bytes;
};

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, int);
   __type(value, struct datarec);
   __uint(max_entries, 1024);
} xdp_stats_map SEC(".maps");

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   /* TODO 1: Fix bound checking errors */
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

/* TODO 3: Implement IP parsing function */
static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
   struct iphdr *ip = (struct iphdr *) (data + *nh_off);
   int hdr_size = sizeof(*ip);
   if((void *)ip + hdr_size > data_end)
      return -1;
   hdr_size = ip->ihl * 4;
   if((void *)ip + hdr_size > data_end)
      return -1;
   *nh_off += hdr_size;
   *iphdr = ip;

   return ip->protocol; /* network-byte-order */
}

/* TODO 5: Implement ICMP parsing function */
static __always_inline int parse_icmphdr(void *data, void *data_end, __u16 *nh_off, struct icmphdr **icmphdr) {
   struct icmphdr *icmp = data + *nh_off;
   int hdr_size = sizeof(*icmp);
   if ((void *)icmp + hdr_size > data_end)
      return -1;
   *nh_off += hdr_size;
   *icmphdr = icmp;

   return icmp->type; /* ICMP type */
}

SEC("xdp")
int xdp_packet_parsing(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   int eth_type;

   bpf_printk("Packet received");

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (eth_type != bpf_ntohs(ETH_P_IP))
      goto pass;

   bpf_printk("Packet is IPv4");

   /* TODO 2: Parse IPv4 packet, pass all NON-ICMP packets */
   struct iphdr *ip;
   int ip_proto = parse_iphdr(data, data_end, &nf_off, &ip);
   if (ip_proto != IPPROTO_ICMP){
      bpf_printk("Packet is not ICMP");
      goto pass;
   }
   bpf_printk("Packet is ICMP");   

   /* TODO 4: Parse ICMP packet, pass all NON-ICMP ECHO packets */
   struct icmphdr *icmp;
   int icmp_type = parse_icmphdr(data, data_end, &nf_off, &icmp);
   if (icmp_type != ICMP_ECHO) {
      bpf_printk("Packet is not ICMP ECHO");
      goto pass;
   }
   bpf_printk("Packet is ICMP ECHO");

   /* ICMP EHCO REPLY packets should goto pass */

   /* TODO 6: Retrieve sequence number from ICMP packet */
   __be16 sequence = icmp->un.echo.sequence;
   bpf_printk("ICMP sequence number: %d", bpf_ntohs(sequence));

   /* TODO 7: Check if sequence number is even 
    * If even, drop packet
    * If odd, goto out, where packets and bytes are counted
    */

   if (bpf_ntohs(sequence) % 2 == 0) {
      bpf_printk("ICMP sequence number is even, dropping packet");
      return XDP_DROP; // Drop packets with even sequence numbers
   } else{
      bpf_printk("ICMP sequence number is odd, passing packet");
      goto out; // Pass packets with odd sequence numbers
   }

out:
   bpf_printk("Packet passed");
   /* TODO 8: Count packets and bytes and store them into an ARRAY map */
   struct datarec *rec;
   int key = 0;

   rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
   if (!rec) {
      bpf_printk("Failed to lookup data record in map");
      return XDP_ABORTED; // Abort if we cannot find the record
   }
   __u64 bytes = data_end - data;
   __sync_fetch_and_add(&rec->rx_packets, 1); // Increment packet count atomically
   __sync_fetch_and_add(&rec->rx_bytes, bytes); // Increment byte count atomically
   bpf_printk("Packet and byte counts updated: packets=%llu, bytes=%llu", rec->rx_packets, rec->rx_bytes);
   goto pass;

pass:
   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";