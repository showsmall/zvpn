//go:build !linux || !ebpf
// +build !linux !ebpf

package ebpf

import (
	"fmt"
	"net"
)

// XDPProgram represents an eBPF XDP program
// Stub implementation when eBPF is not compiled
type XDPProgram struct {
	objs   *xdpObjects
	link   interface{} // link.Link when compiled
	ifName string
}

// LoadXDPProgram loads and attaches the XDP program to a network interface
// This is a stub implementation when eBPF is not compiled
// To enable eBPF, compile the program first: go generate ./vpn/ebpf
func LoadXDPProgram(ifName string) (*XDPProgram, error) {
	return nil, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// AddVPNClient adds a VPN client IP mapping
func (x *XDPProgram) AddVPNClient(vpnIP, clientIP net.IP) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// RemoveVPNClient removes a VPN client IP mapping
func (x *XDPProgram) RemoveVPNClient(vpnIP net.IP) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// AddRoute adds a routing rule with optional metric
func (x *XDPProgram) AddRoute(network *net.IPNet, gateway net.IP, metric int) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// UpdateRoute updates an existing routing rule
func (x *XDPProgram) UpdateRoute(network *net.IPNet, gateway net.IP, metric int) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// DeleteRoute removes a routing rule
func (x *XDPProgram) DeleteRoute(network *net.IPNet) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// AddPolicy adds a policy to eBPF maps
func (x *XDPProgram) AddPolicy(policyID uint32, hookPoint uint32, action uint32,
	srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// AddPolicyWithMask adds a policy to eBPF maps with support for CIDR masks, port ranges, and protocol masks
func (x *XDPProgram) AddPolicyWithMask(policyID uint32, hookPoint uint32, action uint32,
	srcIP, dstIP net.IP, srcIPMask, dstIPMask uint32,
	srcPort, srcPortEnd, dstPort, dstPortEnd uint16,
	protocolMask uint8) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// RemovePolicy removes a policy from eBPF maps
func (x *XDPProgram) RemovePolicy(policyID uint32) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// GetStats returns packet processing statistics
func (x *XDPProgram) GetStats() (uint64, error) {
	if x == nil {
		return 0, fmt.Errorf("eBPF program not loaded")
	}
	return 0, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// GetDetailedStats returns detailed packet processing statistics
// Returns: totalPackets, droppedPackets, error
func (x *XDPProgram) GetDetailedStats() (totalPackets uint64, droppedPackets uint64, err error) {
	if x == nil {
		return 0, 0, fmt.Errorf("eBPF program not loaded")
	}
	return 0, 0, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// GetPolicyStats returns policy match statistics
func (x *XDPProgram) GetPolicyStats(policyID uint32) (uint64, error) {
	if x == nil {
		return 0, fmt.Errorf("eBPF program not loaded")
	}
	return 0, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// Close detaches and closes the XDP program
func (x *XDPProgram) Close() error {
	if x == nil {
		return nil
	}
	if x.objs != nil {
		return x.objs.Close()
	}
	return nil
}

// SetPublicIP sets the public IP for NAT masquerading
func (x *XDPProgram) SetPublicIP(publicIP net.IP) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// GetPublicIP retrieves the configured public IP
func (x *XDPProgram) GetPublicIP() (net.IP, error) {
	if x == nil {
		return nil, fmt.Errorf("eBPF program not loaded")
	}
	return nil, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// SetVPNNetwork sets the VPN network configuration
func (x *XDPProgram) SetVPNNetwork(vpnNetwork string) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// BlockIP blocks an IP address in eBPF (kernel-level blocking)
func (x *XDPProgram) BlockIP(ip net.IP, blockedUntil uint64) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// UnblockIP unblocks an IP address in eBPF
func (x *XDPProgram) UnblockIP(ip net.IP) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// IsIPBlocked checks if an IP is blocked in eBPF
func (x *XDPProgram) IsIPBlocked(ip net.IP) (bool, uint64, error) {
	if x == nil {
		return false, 0, fmt.Errorf("eBPF program not loaded")
	}
	return false, 0, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// RateLimitConfig is in bpf_types.go (mirrors C struct)

// UpdateRateLimitConfig updates the rate limit and DDoS protection configuration in eBPF
func (x *XDPProgram) UpdateRateLimitConfig(config RateLimitConfig) error {
	if x == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// GetRateLimitConfig retrieves the current rate limit and DDoS protection configuration from eBPF
func (x *XDPProgram) GetRateLimitConfig() (RateLimitConfig, error) {
	var config RateLimitConfig
	if x == nil {
		return config, fmt.Errorf("eBPF program not loaded")
	}
	return config, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// xdpObjects stub when eBPF is not compiled
type xdpObjects struct{}

func (x *xdpObjects) Close() error {
	return nil
}
