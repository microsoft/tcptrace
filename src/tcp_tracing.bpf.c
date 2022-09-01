#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif /* END ETH_P_IP */

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif /* END ETH_P_IPV6 */

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define TC_ACT_UNSPEC (-1)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    //__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u64);
} tcp_stats SEC(".maps");

__always_inline struct ethhdr *
get_eth_header(const struct __sk_buff *skb)
{
    if (unlikely(!skb))
    {
        return NULL;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (unlikely(!data || !data_end))
    {
        return NULL;
    }

    if (unlikely(data + sizeof(struct ethhdr) > data_end))
    {
        return NULL;
    }

    return (struct ethhdr *)data;
}

__always_inline struct iphdr *
get_ip_header(const struct __sk_buff *skb, struct ethhdr *eth)
{
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return NULL;
    }

    void *data = (void *)((long)skb->data + sizeof(struct ethhdr));
    void *data_end = (void *)(long)skb->data_end;

    if (unlikely(data + sizeof(struct iphdr) > data_end))
    {
        return NULL;
    }

    return (struct iphdr *)data;
}

__always_inline struct ipv6hdr *
get_ipv6_header(const struct __sk_buff *skb, struct ethhdr *eth)
{
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
    {
        return NULL;
    }

    void *data = (void *)((long)skb->data + sizeof(struct ethhdr));
    void *data_end = (void *)(long)skb->data_end;

    if (unlikely(data + sizeof(struct ipv6hdr) > data_end))
    {
        return NULL;
    }

    return (struct ipv6hdr *)data;
}

__always_inline struct tcphdr *
get_tcp_header(const struct __sk_buff *skb, struct iphdr *ip)
{
    if (!ip)
    {
        return NULL;
    }

    if (unlikely(ip->protocol != IPPROTO_TCP))
    {
        return NULL;
    }

    void *data = (void *)((long)skb->data +
                          sizeof(struct ethhdr) + sizeof(struct iphdr));
    void *data_end = (void *)(long)skb->data_end;

    if (unlikely(data + sizeof(struct tcphdr) > data_end))
    {
        return NULL;
    }

    return (struct tcphdr *)data;
}

__always_inline struct tcphdr *
get_tcp6_header(const struct __sk_buff *skb, struct ipv6hdr *ip6)
{
    if (!ip6)
    {
        return NULL;
    }

    if (unlikely(ip6->nexthdr != IPPROTO_TCP))
    {
        return NULL;
    }

    void *data = (void *)((long)skb->data +
                          sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
    void *data_end = (void *)(long)skb->data_end;

    if (unlikely(data + sizeof(struct tcphdr) > data_end))
    {
        return NULL;
    }

    return (struct tcphdr *)data;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb_trace(struct sock *sk, struct sk_buff *skb)
{
    const int idx = 2;
    u64 *rxmit_count = bpf_map_lookup_elem(&tcp_stats, &idx);

    if (rxmit_count)
    {
        __sync_fetch_and_add(rxmit_count, 1);
    }

    return 0;
}

SEC("classifier")
int tc_ingress_prog(struct __sk_buff *skb)
{
    struct ethhdr *eth = get_eth_header(skb);

    if (unlikely(eth == NULL))
    {
        return TC_ACT_UNSPEC;
    }

    struct iphdr *ip = get_ip_header(skb, eth);
    struct ipv6hdr *ipv6 = get_ipv6_header(skb, eth);
    struct tcphdr *tcp = ip
                             ? get_tcp_header(skb, ip)
                             : get_tcp6_header(skb, ipv6);

    if (!tcp)
    {
        return TC_ACT_UNSPEC;
    }

    const int idx = 0;
    u64 *ingress_count = bpf_map_lookup_elem(&tcp_stats, &idx);

    if (ingress_count)
    {
        __sync_fetch_and_add(ingress_count, 1);
    }

    return TC_ACT_UNSPEC;
}

SEC("classifier")
int tc_egress_prog(struct __sk_buff *skb)
{
    struct ethhdr *eth = get_eth_header(skb);

    if (unlikely(eth == NULL))
    {
        return TC_ACT_UNSPEC;
    }

    struct iphdr *ip = get_ip_header(skb, eth);
    struct ipv6hdr *ipv6 = get_ipv6_header(skb, eth);
    struct tcphdr *tcp = ip
                             ? get_tcp_header(skb, ip)
                             : get_tcp6_header(skb, ipv6);

    if (!tcp)
    {
        return TC_ACT_UNSPEC;
    }

    const int idx = 1;
    u64 *egress_count = bpf_map_lookup_elem(&tcp_stats, &idx);

    if (egress_count)
    {
        __sync_fetch_and_add(egress_count, 1);
    }

    return TC_ACT_UNSPEC;
}
