#include "include/vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "include/bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define POLICY_ACTION_ALLOW 0
#define POLICY_ACTION_DENY 1
#define POLICY_ACTION_REDIRECT 2

#define HOOK_PRE_ROUTING 0
#define HOOK_POST_ROUTING 1
#define HOOK_FORWARD 2
#define HOOK_INPUT 3
#define HOOK_OUTPUT 4

#define STAT_TOTAL_PACKETS 0
#define STAT_DROPPED_PACKETS 1
#define STAT_RATE_LIMIT_DROPS 2
#define STAT_DDOS_DROPS 3
#define STAT_BLOCKED_PACKETS 4
#define STAT_POLICY_DENIED_PACKETS 5

#define POLICY_CHAIN_DEPTH 32

struct policy_entry {
	__u32 policy_id;
	__u32 action;
	__u32 hook_point;
	__u32 priority;
	__u32 src_ip;
	__u32 dst_ip;
	__u32 src_ip_mask;
	__u32 dst_ip_mask;
	__u16 src_port;
	__u16 dst_port;
	__u16 src_port_end;
	__u16 dst_port_end;
	__u8 protocol;
	__u8 protocol_mask;
	__u8 flags;
};

struct policy_chain_key {
	__u32 hook_point;
	__u32 index;
};

struct policy_event {
	__u32 policy_id;
	__u32 action;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u32 timestamp;
};

struct rate_limit_config {
	__u8 enable_rate_limit;
	__u8 _pad0[7];
	__u64 rate_limit_per_ip;
	__u8 enable_ddos_protection;
	__u8 _pad1[7];
	__u64 ddos_threshold;
	__u64 ddos_block_duration;
};

struct rate_limit_entry {
	__u64 tokens;
	__u64 last_update;
	__u64 rate;
	__u64 burst;
};

struct ddos_tracker {
	__u64 packet_count;
	__u64 window_start;
	__u64 block_until;
};

struct packet_ports {
	__u16 src_port;
	__u16 dst_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u32);
} vpn_clients SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} server_egress_ip SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} vpn_network_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 5);
	__type(key, __u32);
	__type(value, __u8);
} policy_chain_status SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, struct policy_entry);
} policies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct policy_chain_key);
	__type(value, __u32);
} policy_chains SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 10);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u64);
} policy_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 2048);
	__type(value, struct policy_event);
} policy_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_limit_config);
} rate_limit_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct ddos_tracker);
} ddos_tracker_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} blocked_ips_map SEC(".maps");

static __always_inline void count_stat(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&stats, &key);

	if (value)
		(*value)++;
}

static __always_inline __u8 get_src_ip_match_type(__u8 flags)
{
	return flags & 0x3;
}

static __always_inline __u8 get_dst_ip_match_type(__u8 flags)
{
	return (flags >> 2) & 0x3;
}

static __always_inline __u8 get_src_port_match_type(__u8 flags)
{
	return (flags >> 4) & 0x3;
}

static __always_inline __u8 get_dst_port_match_type(__u8 flags)
{
	return (flags >> 6) & 0x3;
}

static __always_inline int match_ip(__u32 actual, __u32 expected, __u32 mask, __u8 match_type)
{
	if (match_type == 1)
		return expected == 0;

	if (match_type == 2) {
		if (mask == 0)
			return expected == 0;
		return (actual & mask) == (expected & mask);
	}

	return actual == expected;
}

static __always_inline int match_port(__u16 actual, __u16 expected, __u16 expected_end,
					      __u8 match_type)
{
	if (match_type == 1)
		return expected == 0;

	if (match_type == 2) {
		if (expected_end == 0)
			return actual == expected;
		return actual >= expected && actual <= expected_end;
	}

	if (expected_end != 0 && expected_end != expected)
		return actual >= expected && actual <= expected_end;

	return actual == expected;
}

static __always_inline int match_protocol(__u8 actual, __u8 expected, __u8 protocol_mask)
{
	if (protocol_mask == 0)
		return expected == 0 || actual == expected;

	if (actual == IPPROTO_TCP)
		return (protocol_mask & 0x01) != 0;
	if (actual == IPPROTO_UDP)
		return (protocol_mask & 0x02) != 0;
	if (actual == IPPROTO_ICMP)
		return (protocol_mask & 0x04) != 0;

	return 0;
}

static __always_inline int extract_ports(struct iphdr *ip, void *data_end,
						 struct packet_ports *ports)
{
	void *transport = (void *)ip + (ip->ihl * 4);

	ports->src_port = 0;
	ports->dst_port = 0;

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = transport;

		if ((void *)(tcp + 1) > data_end)
			return 0;

		ports->src_port = bpf_ntohs(tcp->source);
		ports->dst_port = bpf_ntohs(tcp->dest);
		return 1;
	}

	if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = transport;

		if ((void *)(udp + 1) > data_end)
			return 0;

		ports->src_port = bpf_ntohs(udp->source);
		ports->dst_port = bpf_ntohs(udp->dest);
		return 1;
	}

	return 1;
}

static __always_inline int policy_matches(struct policy_entry *policy, struct iphdr *ip,
						  struct packet_ports *ports)
{
	if ((policy->src_ip != 0 || policy->src_ip_mask != 0) &&
	    !match_ip(ip->saddr, policy->src_ip, policy->src_ip_mask,
		      get_src_ip_match_type(policy->flags)))
		return 0;

	if ((policy->dst_ip != 0 || policy->dst_ip_mask != 0) &&
	    !match_ip(ip->daddr, policy->dst_ip, policy->dst_ip_mask,
		      get_dst_ip_match_type(policy->flags)))
		return 0;

	if ((policy->protocol != 0 || policy->protocol_mask != 0) &&
	    !match_protocol(ip->protocol, policy->protocol, policy->protocol_mask))
		return 0;

	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return 1;

	if (!match_port(ports->src_port, policy->src_port, policy->src_port_end,
			get_src_port_match_type(policy->flags)))
		return 0;

	if (!match_port(ports->dst_port, policy->dst_port, policy->dst_port_end,
			get_dst_port_match_type(policy->flags)))
		return 0;

	return 1;
}

static __always_inline void record_policy_hit(__u32 policy_id, struct policy_entry *policy,
					      struct iphdr *ip, struct packet_ports *ports)
{
	__u64 init = 1;
	__u64 *count = bpf_map_lookup_elem(&policy_stats, &policy_id);
	struct policy_event event = {
		.policy_id = policy_id,
		.action = policy->action,
		.src_ip = ip->saddr,
		.dst_ip = ip->daddr,
		.src_port = ports->src_port,
		.dst_port = ports->dst_port,
		.protocol = ip->protocol,
		.timestamp = (__u32)(bpf_ktime_get_ns() / 1000000ULL),
	};

	if (count)
		(*count)++;
	else
		bpf_map_update_elem(&policy_stats, &policy_id, &init, BPF_ANY);

	bpf_map_push_elem(&policy_events, &event, 0);
}

static __always_inline int execute_policy_chain(__u32 hook_point, struct iphdr *ip,
						void *data_end, __u32 *action)
{
	struct packet_ports ports = {};
	__u8 *has_policies = bpf_map_lookup_elem(&policy_chain_status, &hook_point);

	if (!has_policies || *has_policies == 0)
		return 0;

	if (!extract_ports(ip, data_end, &ports))
		return 0;

#pragma unroll
	for (int i = 0; i < POLICY_CHAIN_DEPTH; i++) {
		struct policy_chain_key key = {
			.hook_point = hook_point,
			.index = i,
		};
		__u32 *policy_id = bpf_map_lookup_elem(&policy_chains, &key);
		struct policy_entry *policy;

		if (!policy_id || *policy_id == 0)
			break;

		policy = bpf_map_lookup_elem(&policies, policy_id);
		if (!policy)
			continue;

		if (!policy_matches(policy, ip, &ports))
			continue;

		record_policy_hit(*policy_id, policy, ip, &ports);
		*action = policy->action;
		return 1;
	}

	return 0;
}

static __always_inline int is_vpn_network(__u32 ip)
{
	__u32 key = 0;
	__u32 *vpn_net = bpf_map_lookup_elem(&vpn_network_config, &key);
	__u32 default_net = 0x0A080000;
	__u32 default_mask = 0xFFFFFF00;
	__u32 *vpn_mask;

	if (!vpn_net)
		return (ip & default_mask) == default_net;

	key = 1;
	vpn_mask = bpf_map_lookup_elem(&vpn_network_config, &key);
	if (!vpn_mask)
		return (ip & default_mask) == (*vpn_net & default_mask);

	return (ip & *vpn_mask) == (*vpn_net & *vpn_mask);
}

static __always_inline __u32 get_server_vpn_ip(void)
{
	__u32 key = 0;
	__u32 *vpn_net = bpf_map_lookup_elem(&vpn_network_config, &key);

	if (!vpn_net)
		return 0x0A080001;

	return *vpn_net + 1;
}

static __always_inline int should_bypass_security(struct iphdr *ip, void *data_end,
						  __u32 server_public_ip)
{
	struct tcphdr *tcp;
	__u16 src_port;
	__u16 dst_port;

	if (server_public_ip == 0 || ip->daddr != server_public_ip || ip->protocol != IPPROTO_TCP)
		return 0;

	tcp = (void *)ip + (ip->ihl * 4);
	if ((void *)(tcp + 1) > data_end)
		return 0;

	if (tcp->fin || tcp->rst || tcp->syn)
		return 1;

	src_port = bpf_ntohs(tcp->source);
	dst_port = bpf_ntohs(tcp->dest);
	if (src_port == 443 || dst_port == 443 || src_port == 8443 || dst_port == 8443)
		return 1;

	return 0;
}

static __always_inline int check_rate_limit(__u32 ip)
{
	__u32 key = 0;
	struct rate_limit_config *config = bpf_map_lookup_elem(&rate_limit_config_map, &key);
	struct rate_limit_entry *entry;
	__u64 now;
	__u64 elapsed;
	__u64 tokens_to_add;
	__u64 new_tokens;

	if (!config || !config->enable_rate_limit || config->rate_limit_per_ip == 0)
		return 1;

	entry = bpf_map_lookup_elem(&rate_limit_map, &ip);
	now = bpf_ktime_get_ns();
	if (!entry) {
		struct rate_limit_entry init = {
			.tokens = config->rate_limit_per_ip,
			.last_update = now,
			.rate = config->rate_limit_per_ip,
			.burst = config->rate_limit_per_ip * 2,
		};

		bpf_map_update_elem(&rate_limit_map, &ip, &init, BPF_ANY);
		return 1;
	}

	elapsed = now - entry->last_update;
	tokens_to_add = (elapsed * entry->rate) / 1000000000ULL;
	new_tokens = entry->tokens + tokens_to_add;
	if (new_tokens > entry->burst)
		new_tokens = entry->burst;

	if (new_tokens >= 1) {
		entry->tokens = new_tokens - 1;
		entry->last_update = now;
		return 1;
	}

	entry->last_update = now;
	return 0;
}

static __always_inline int check_ddos_protection(__u32 ip)
{
	__u32 key = 0;
	struct rate_limit_config *config = bpf_map_lookup_elem(&rate_limit_config_map, &key);
	struct ddos_tracker *tracker;
	__u64 now;
	__u64 window_size = 1000000000ULL;

	if (!config || !config->enable_ddos_protection || config->ddos_threshold == 0)
		return 1;

	tracker = bpf_map_lookup_elem(&ddos_tracker_map, &ip);
	now = bpf_ktime_get_ns();
	if (!tracker) {
		struct ddos_tracker init = {
			.packet_count = 1,
			.window_start = now,
			.block_until = 0,
		};

		bpf_map_update_elem(&ddos_tracker_map, &ip, &init, BPF_ANY);
		return 1;
	}

	if (tracker->block_until > 0 && now < tracker->block_until)
		return 0;

	if (tracker->block_until > 0 && now >= tracker->block_until) {
		tracker->block_until = 0;
		tracker->packet_count = 0;
		tracker->window_start = now;
	}

	if (now - tracker->window_start >= window_size) {
		tracker->packet_count = 1;
		tracker->window_start = now;
		return 1;
	}

	tracker->packet_count++;
	if (tracker->packet_count > config->ddos_threshold) {
		tracker->block_until = now + config->ddos_block_duration;
		return 0;
	}

	return 1;
}

static __always_inline int check_blocked_ip(__u32 ip)
{
	__u64 *blocked_until = bpf_map_lookup_elem(&blocked_ips_map, &ip);

	if (!blocked_until)
		return 0;

	if (*blocked_until == 0)
		return 1;

	if (bpf_ktime_get_ns() >= *blocked_until) {
		bpf_map_delete_elem(&blocked_ips_map, &ip);
		return 0;
	}

	return 1;
}

static __always_inline int handle_policy_result(__u32 action)
{
	if (action == POLICY_ACTION_DENY) {
		count_stat(STAT_DROPPED_PACKETS);
		count_stat(STAT_POLICY_DENIED_PACKETS);
		return XDP_DROP;
	}

	return XDP_PASS;
}

SEC("xdp")
int xdp_vpn_forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u32 key = 0;
	__u32 action = POLICY_ACTION_ALLOW;
	__u32 *client_ip;
	__u32 *server_public_ip;
	__u32 server_public_ip_value = 0;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	if (ip->ihl < 5)
		return XDP_PASS;

	if ((void *)ip + (ip->ihl * 4) > data_end)
		return XDP_PASS;

	count_stat(STAT_TOTAL_PACKETS);

	if (is_vpn_network(ip->saddr) && is_vpn_network(ip->daddr))
		return XDP_PASS;

	server_public_ip = bpf_map_lookup_elem(&server_egress_ip, &key);
	if (server_public_ip && *server_public_ip != 0)
		server_public_ip_value = *server_public_ip;

	if (should_bypass_security(ip, data_end, server_public_ip_value))
		return XDP_PASS;

	if (check_blocked_ip(ip->saddr)) {
		count_stat(STAT_DROPPED_PACKETS);
		count_stat(STAT_BLOCKED_PACKETS);
		return XDP_DROP;
	}

	if (!check_rate_limit(ip->saddr)) {
		count_stat(STAT_DROPPED_PACKETS);
		count_stat(STAT_RATE_LIMIT_DROPS);
		return XDP_DROP;
	}

	if (!check_ddos_protection(ip->saddr)) {
		count_stat(STAT_DROPPED_PACKETS);
		count_stat(STAT_DDOS_DROPS);
		return XDP_DROP;
	}

	client_ip = bpf_map_lookup_elem(&vpn_clients, &ip->saddr);
	if (client_ip) {
		if (execute_policy_chain(HOOK_PRE_ROUTING, ip, data_end, &action))
			return handle_policy_result(action);
		if (execute_policy_chain(HOOK_POST_ROUTING, ip, data_end, &action))
			return handle_policy_result(action);
		return XDP_PASS;
	}

	if (ip->daddr == get_server_vpn_ip()) {
		if (execute_policy_chain(HOOK_INPUT, ip, data_end, &action))
			return handle_policy_result(action);
		return XDP_PASS;
	}

	if (is_vpn_network(ip->daddr)) {
		if (execute_policy_chain(HOOK_PRE_ROUTING, ip, data_end, &action))
			return handle_policy_result(action);
		if (execute_policy_chain(HOOK_FORWARD, ip, data_end, &action))
			return handle_policy_result(action);
		return XDP_PASS;
	}

	if (server_public_ip_value != 0 && ip->daddr == server_public_ip_value)
		return XDP_PASS;

	if (execute_policy_chain(HOOK_PRE_ROUTING, ip, data_end, &action))
		return handle_policy_result(action);
	if (execute_policy_chain(HOOK_OUTPUT, ip, data_end, &action))
		return handle_policy_result(action);

	return XDP_PASS;
}
