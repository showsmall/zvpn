#ifndef __BPF_COMPAT_H__
#define __BPF_COMPAT_H__

/* bpf_map_update_elem flags - not always in vmlinux BTF */
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

/* ETH_P_IP - from linux/if_ether.h, needed when vmlinux_net.h not included */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* struct xdp_md - XDP context, from include/uapi/linux/bpf.h
 * vmlinux BTF may not expose this; bpf_helper_defs.h only forward-declares it */
#ifndef __xdp_md_defined
#define __xdp_md_defined
struct xdp_md {
	unsigned int data;
	unsigned int data_end;
	unsigned int data_meta;
	unsigned int ingress_ifindex;
	unsigned int rx_queue_index;
};
#endif

#endif /* __BPF_COMPAT_H__ */
