#include <uapi/linux/if_ether.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>

#define TCP_FLAGS_OFFSET 13
#define IPPROTO_TCP 6

struct pkt_info {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  tcp_flags; 
};

BPF_PERF_OUTPUT(pkt_events);

int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* parseamento ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    /* parseamento ip */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    u32 ip_hdr_len = ip->ihl * 4;
    
    if (ip_hdr_len < sizeof(*ip)) return XDP_PASS;

    /* parseamento tcp */
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    /* preenchimento e envio */
    struct pkt_info info = {};
    info.src_ip = bpf_ntohl(ip->saddr);
    info.dst_ip = bpf_ntohl(ip->daddr);
    info.src_port = bpf_ntohs(tcp->source);
    info.dst_port = bpf_ntohs(tcp->dest);

    info.tcp_flags = ((u8 *)tcp)[TCP_FLAGS_OFFSET];

    pkt_events.perf_submit(ctx, &info, sizeof(info));
    
    return XDP_PASS;
}