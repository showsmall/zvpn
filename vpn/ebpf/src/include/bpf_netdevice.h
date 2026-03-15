#ifndef __BPF_NETDEVICE_H__
#define __BPF_NETDEVICE_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// enum netdev_state_t {
//         __LINK_STATE_START,
//         __LINK_STATE_PRESENT,
//         __LINK_STATE_NOCARRIER,
//         __LINK_STATE_LINKWATCH_PENDING,
//         __LINK_STATE_DORMANT,
//         __LINK_STATE_TESTING,
// };

static __always_inline bool netif_running(const struct net_device *dev)
{
	unsigned long state = BPF_CORE_READ(dev, state);

	return !!((1<<__LINK_STATE_START) & state);
}

static __always_inline bool netif_carrier_ok(const struct net_device *dev)
{
	unsigned long state = BPF_CORE_READ(dev, state);

	return !((1<<__LINK_STATE_NOCARRIER) & state);
}

static __always_inline unsigned int
netif_get_flags(const struct net_device *dev)
{
	unsigned int flags = BPF_CORE_READ(dev, flags);

	flags = flags & ~(IFF_RUNNING | IFF_LOWER_UP);

	if (netif_running(dev)) {
		if (netif_carrier_ok(dev))
			flags |= IFF_LOWER_UP;
		// FIXME ...
	}
	
	return flags;
}

#endif
