// Package ebpf provides eBPF loaders and map operations for XDP and TC programs.
//
// Architecture (huatuo-style): C为主、Go只负责装载和map操作.
// - C: All packet logic (forwarding, NAT, policy, rate limit) in xdp_program.c / tc_nat.c
// - Go: Load .o, attach programs, Put/Delete/Lookup maps only
package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
)

var errIPv6NotSupported = errors.New("IPv6 not supported")

// Types mirror C structs in xdp_program.c / tc_nat.c.

// RateLimitConfig mirrors struct rate_limit_config in C.
type RateLimitConfig struct {
	EnableRateLimit      uint8
	_                    [7]byte
	RateLimitPerIP       uint64
	EnableDDoSProtection uint8
	_                    [7]byte
	DDoSThreshold        uint64
	DDoSBlockDuration    uint64
}

// policyEntry mirrors struct policy_entry in C (for map Put/Lookup).
type policyEntry struct {
	PolicyID     uint32
	Action       uint32
	HookPoint    uint32
	Priority     uint32
	SrcIP        uint32
	DstIP        uint32
	SrcIPMask    uint32
	DstIPMask    uint32
	SrcPort      uint16
	DstPort      uint16
	SrcPortEnd   uint16
	DstPortEnd   uint16
	Protocol     uint8
	ProtocolMask uint8
	Flags        uint8
}

// policyChainKey mirrors struct policy_chain_key in C.
type policyChainKey struct {
	HookPoint uint32
	Index     uint32
}

// Uint32ToIP converts uint32 (network byte order) to net.IP.
func Uint32ToIP(ip uint32) net.IP {
	return net.IP{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
}

// IPToUint32 converts net.IP to uint32 (network byte order).
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// ParseCIDRToUint32 parses an IPv4 CIDR and returns (networkAddr, mask) as uint32.
// Used for vpn_network_config map.
func ParseCIDRToUint32(cidr string) (network, mask uint32, err error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, err
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return 0, 0, errIPv6NotSupported
	}
	network = binary.BigEndian.Uint32(ip)
	maskBytes := ipNet.Mask
	if len(maskBytes) < 4 {
		return 0, 0, errIPv6NotSupported
	}
	mask = binary.BigEndian.Uint32(maskBytes)
	return network, mask, nil
}
