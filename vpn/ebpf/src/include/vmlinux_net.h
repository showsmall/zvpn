#ifndef __VMLINUX_NET_H__
#define __VMLINUX_NET_H__

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define IFNAMSIZ        16

#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define AF_INET         2       /* Internet IP Protocol         */

#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

// skb_network_header - get the network header from sk_buff
static inline unsigned char *skb_network_header(struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
}

// skb_transport_header - get the transport header from sk_buff
static inline unsigned char *skb_transport_header(struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header);
}
#endif
