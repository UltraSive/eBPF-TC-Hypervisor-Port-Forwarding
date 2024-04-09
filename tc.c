#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// Define the eBPF maps to store the forwarding mappings
BPF_MAP_DEF(ingress_port_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct forward_key),
    .value_size = sizeof(struct forward_value),
    .max_entries = 1024,
};
BPF_MAP_ADD(ingress_port_map);

BPF_MAP_DEF(egress_port_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct forward_key),
    .value_size = sizeof(struct forward_value),
    .max_entries = 1024,
};
BPF_MAP_ADD(egress_port_map);

struct forward_key {
    uint32_t src_ip;
    uint16_t src_port;
};

struct forward_value {
    uint32_t dst_ip;
    uint16_t dst_port;
};

SEC("tc")
int port_forwarding(struct __sk_buff *skb) {
    // Parse the Ethernet, IP, and TCP/UDP headers
    struct ethhdr *eth = bpf_hdr_pointer(skb);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    void *transport_header = (void *)ip + (ip->ihl << 2);

    // Check if the packet is TCP or UDP
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct forward_key key;
        struct forward_value *value;

        // Check if the packet is ingress (incoming)
        if (skb->pkt_type == PACKET_HOST) {
            // Ingress logic
            if (ip->daddr == htonl(0x0A000105)) {  // Destination IP is 10.0.1.5
                if (ip->protocol == IPPROTO_TCP) {
                    struct tcphdr *tcp = (struct tcphdr *)transport_header;
                    key = (struct forward_key){
                        .src_ip = ip->saddr,
                        .src_port = tcp->source,
                    };
                } else if (ip->protocol == IPPROTO_UDP) {
                    struct udphdr *udp = (struct udphdr *)transport_header;
                    key = (struct forward_key){
                        .src_ip = ip->saddr,
                        .src_port = udp->source,
                    };
                }

                value = bpf_map_lookup_elem(&ingress_port_map, &key);
                if (value) {
                    // Modify the destination IP and port of the packet
                    ip->daddr = value->dst_ip;
                    if (ip->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcp = (struct tcphdr *)transport_header;
                        tcp->dest = value->dst_port;
                    } else if (ip->protocol == IPPROTO_UDP) {
                        struct udphdr *udp = (struct udphdr *)transport_header;
                        udp->dest = value->dst_port;
                    }
                }
            }
        }
        // Check if the packet is egress (outgoing)
        else if (skb->pkt_type == PACKET_OUTGOING) {
            // Egress logic
            if (ip->saddr == htonl(0x0A000105)) {  // Source IP is 10.0.1.5
                if (ip->protocol == IPPROTO_TCP) {
                    struct tcphdr *tcp = (struct tcphdr *)transport_header;
                    key = (struct forward_key){
                        .src_ip = ip->daddr,
                        .src_port = tcp->dest,
                    };
                } else if (ip->protocol == IPPROTO_UDP) {
                    struct udphdr *udp = (struct udphdr *)transport_header;
                    key = (struct forward_key){
                        .src_ip = ip->daddr,
                        .src_port = udp->dest,
                    };
                }

                value = bpf_map_lookup_elem(&egress_port_map, &key);
                if (value) {
                    // Modify the source IP and port of the packet
                    ip->saddr = value->dst_ip;
                    if (ip->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcp = (struct tcphdr *)transport_header;
                        tcp->source = value->dst_port;
                    } else if (ip->protocol == IPPROTO_UDP) {
                        struct udphdr *udp = (struct udphdr *)transport_header;
                        udp->source = value->dst_port;
                    }
                }
            }
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
