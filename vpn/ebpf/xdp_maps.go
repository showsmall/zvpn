//go:build linux && ebpf
// +build linux,ebpf

package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// Map operations for XDP. C为主、Go只负责 Put/Delete/Lookup.
// policyChainDepth must match POLICY_CHAIN_DEPTH in xdp_program.c
const policyChainDepth = 32

// AddVPNClient adds a VPN client IP mapping to vpn_clients map.
func (x *XDPProgram) AddVPNClient(vpnIP, clientIP net.IP) error {
	if x == nil || x.vpnClients == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	if err := x.vpnClients.Put(IPToUint32(vpnIP), IPToUint32(clientIP)); err != nil {
		return fmt.Errorf("add VPN client: %w", err)
	}
	return nil
}

// RemoveVPNClient removes a VPN client IP mapping.
func (x *XDPProgram) RemoveVPNClient(vpnIP net.IP) error {
	if x == nil || x.vpnClients == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	if err := x.vpnClients.Delete(IPToUint32(vpnIP)); err != nil {
		return fmt.Errorf("remove VPN client: %w", err)
	}
	return nil
}

// AddRoute, UpdateRoute, DeleteRoute: routes are handled by kernel, no-op for compatibility.
func (x *XDPProgram) AddRoute(network *net.IPNet, gateway net.IP, metric int) error   { return nil }
func (x *XDPProgram) UpdateRoute(network *net.IPNet, gateway net.IP, metric int) error { return nil }
func (x *XDPProgram) DeleteRoute(network *net.IPNet) error                            { return nil }

// AddPolicy adds a policy to policies map and policy_chains.
func (x *XDPProgram) AddPolicy(policyID uint32, hookPoint uint32, action uint32,
	srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) error {
	if x == nil || x.policiesMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	entry := policyEntry{
		PolicyID:     policyID,
		Action:       action,
		HookPoint:    hookPoint,
		Priority:     policyID,
		SrcIP:        IPToUint32(srcIP),
		DstIP:        IPToUint32(dstIP),
		SrcIPMask:    0xFFFFFFFF,
		DstIPMask:    0xFFFFFFFF,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		SrcPortEnd:   0,
		DstPortEnd:   0,
		Protocol:     protocol,
		ProtocolMask: 0,
		Flags:        0,
	}
	if err := x.policiesMap.Put(policyID, entry); err != nil {
		return fmt.Errorf("add policy: %w", err)
	}
	return x.updatePolicyChainWithPriority(x.policiesMap, x.policyChains, x.policyChainStatus, policyID, hookPoint, policyID)
}

// AddPolicyWithMask adds a policy with CIDR masks, port ranges, protocol masks.
func (x *XDPProgram) AddPolicyWithMask(policyID uint32, hookPoint uint32, action uint32,
	srcIP, dstIP net.IP, srcIPMask, dstIPMask uint32,
	srcPort, srcPortEnd, dstPort, dstPortEnd uint16,
	protocolMask uint8) error {
	if x == nil || x.policiesMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	const (
		flagSrcIPShift = 0
		flagDstIPShift = 2
		flagSrcPortShift = 4
		flagDstPortShift = 6
	)
	srcMatchType := uint8(0)
	if srcIPMask != 0 && srcIPMask != 0xFFFFFFFF {
		srcMatchType = 2
	} else if IPToUint32(srcIP) == 0 {
		srcMatchType = 1
	}
	dstMatchType := uint8(0)
	if dstIPMask != 0 && dstIPMask != 0xFFFFFFFF {
		dstMatchType = 2
	} else if IPToUint32(dstIP) == 0 {
		dstMatchType = 1
	}
	srcPortMatchType := uint8(0)
	if srcPortEnd != 0 && srcPortEnd != srcPort {
		srcPortMatchType = 2
	} else if srcPort == 0 {
		srcPortMatchType = 1
	}
	dstPortMatchType := uint8(0)
	if dstPortEnd != 0 && dstPortEnd != dstPort {
		dstPortMatchType = 2
	} else if dstPort == 0 {
		dstPortMatchType = 1
	}
	entry := policyEntry{
		PolicyID:     policyID,
		Action:       action,
		HookPoint:    hookPoint,
		Priority:     policyID,
		SrcIP:        IPToUint32(srcIP),
		DstIP:        IPToUint32(dstIP),
		SrcIPMask:    srcIPMask,
		DstIPMask:    dstIPMask,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		SrcPortEnd:   srcPortEnd,
		DstPortEnd:   dstPortEnd,
		Protocol:     0,
		ProtocolMask: protocolMask,
		Flags:        srcMatchType<<flagSrcIPShift | dstMatchType<<flagDstIPShift |
			srcPortMatchType<<flagSrcPortShift | dstPortMatchType<<flagDstPortShift,
	}
	if err := x.policiesMap.Put(policyID, entry); err != nil {
		return fmt.Errorf("add policy: %w", err)
	}
	return x.updatePolicyChainWithPriority(x.policiesMap, x.policyChains, x.policyChainStatus, policyID, hookPoint, entry.Priority)
}

func (x *XDPProgram) updatePolicyChainWithPriority(policiesMap, policyChains, policyChainStatus *ebpf.Map, policyID, hookPoint, priority uint32) error {
	type chainEntry struct {
		ID       uint32
		Priority uint32
	}
	existing := make([]chainEntry, 0, policyChainDepth)
	for i := uint32(0); i < policyChainDepth; i++ {
		key := policyChainKey{HookPoint: hookPoint, Index: i}
		var id uint32
		if err := policyChains.Lookup(key, &id); err == nil && id != 0 {
			var p policyEntry
			if err := policiesMap.Lookup(id, &p); err == nil {
				existing = append(existing, chainEntry{ID: id, Priority: p.Priority})
			}
		}
	}
	for _, ep := range existing {
		if ep.ID == policyID {
			return nil
		}
	}
	if len(existing) >= policyChainDepth {
		return fmt.Errorf("policy chain full (%d) at hook point %d", policyChainDepth, hookPoint)
	}
	existing = append(existing, chainEntry{ID: policyID, Priority: priority})
	for i := 0; i < len(existing)-1; i++ {
		for j := i + 1; j < len(existing); j++ {
			if existing[i].Priority > existing[j].Priority {
				existing[i], existing[j] = existing[j], existing[i]
			}
		}
	}
	for i := uint32(0); i < policyChainDepth; i++ {
		policyChains.Delete(policyChainKey{HookPoint: hookPoint, Index: i})
	}
	for i, ep := range existing {
		if err := policyChains.Put(policyChainKey{HookPoint: hookPoint, Index: uint32(i)}, ep.ID); err != nil {
			return fmt.Errorf("add policy to chain: %w", err)
		}
	}
	hasPolicies := uint8(0)
	if len(existing) > 0 {
		hasPolicies = 1
	}
	return policyChainStatus.Put(hookPoint, hasPolicies)
}

// RemovePolicy removes a policy from policies and policy_chains.
func (x *XDPProgram) RemovePolicy(policyID uint32) error {
	if x == nil || x.policiesMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	var p policyEntry
	hookPoint := uint32(0)
	if err := x.policiesMap.Lookup(policyID, &p); err == nil {
		hookPoint = p.HookPoint
	}
	if err := x.policiesMap.Delete(policyID); err != nil {
		return fmt.Errorf("remove policy: %w", err)
	}
	if hookPoint > 0 {
		for i := uint32(0); i < policyChainDepth; i++ {
			key := policyChainKey{HookPoint: hookPoint, Index: i}
			var id uint32
			if err := x.policyChains.Lookup(key, &id); err == nil && id == policyID {
				x.policyChains.Delete(key)
				for j := i + 1; j < policyChainDepth; j++ {
					nextKey := policyChainKey{HookPoint: hookPoint, Index: j}
					var nextID uint32
					if err := x.policyChains.Lookup(nextKey, &nextID); err == nil && nextID != 0 {
						x.policyChains.Put(key, nextID)
						x.policyChains.Delete(nextKey)
						i = j - 1
					} else {
						break
					}
				}
				break
			}
		}
		hasPolicies := uint8(0)
		for i := uint32(0); i < policyChainDepth; i++ {
			var id uint32
			if err := x.policyChains.Lookup(policyChainKey{HookPoint: hookPoint, Index: i}, &id); err == nil && id != 0 {
				hasPolicies = 1
				break
			}
		}
		x.policyChainStatus.Put(hookPoint, hasPolicies)
	}
	for hp := uint32(0); hp < 5; hp++ {
		for i := uint32(0); i < policyChainDepth; i++ {
			key := policyChainKey{HookPoint: hp, Index: i}
			var id uint32
			if err := x.policyChains.Lookup(key, &id); err == nil && id == policyID {
				x.policyChains.Put(key, uint32(0))
				break
			}
		}
		hasPolicies := uint8(0)
		for i := uint32(0); i < policyChainDepth; i++ {
			var id uint32
			if err := x.policyChains.Lookup(policyChainKey{HookPoint: hp, Index: i}, &id); err == nil && id != 0 {
				hasPolicies = 1
				break
			}
		}
		x.policyChainStatus.Put(hp, hasPolicies)
	}
	return nil
}

// GetStats returns total packets from stats map.
func (x *XDPProgram) GetStats() (uint64, error) {
	if x == nil || x.stats == nil {
		return 0, fmt.Errorf("eBPF program not loaded")
	}
	var values []uint64
	if err := x.stats.Lookup(uint32(0), &values); err != nil {
		return 0, fmt.Errorf("get stats: %w", err)
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

// GetDetailedStats returns totalPackets and droppedPackets.
func (x *XDPProgram) GetDetailedStats() (totalPackets uint64, droppedPackets uint64, err error) {
	if x == nil || x.stats == nil {
		return 0, 0, fmt.Errorf("eBPF program not loaded")
	}
	var values0 []uint64
	if err := x.stats.Lookup(uint32(0), &values0); err != nil {
		return 0, 0, fmt.Errorf("get stats: %w", err)
	}
	for _, v := range values0 {
		totalPackets += v
	}
	var values1 []uint64
	if err := x.stats.Lookup(uint32(1), &values1); err == nil {
		for _, v := range values1 {
			droppedPackets += v
		}
	}
	return totalPackets, droppedPackets, nil
}

// GetPolicyStats returns policy match count.
func (x *XDPProgram) GetPolicyStats(policyID uint32) (uint64, error) {
	if x == nil || x.policyStats == nil {
		return 0, fmt.Errorf("eBPF program not loaded")
	}
	var values []uint64
	if err := x.policyStats.Lookup(policyID, &values); err != nil {
		return 0, fmt.Errorf("get policy stats: %w", err)
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

// SetPublicIP sets server egress IP in map.
func (x *XDPProgram) SetPublicIP(publicIP net.IP) error {
	if x == nil || x.serverEgressIPMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	ipUint32 := IPToUint32(publicIP)
	if ipUint32 == 0 {
		return fmt.Errorf("invalid IPv4 address")
	}
	if err := x.serverEgressIPMap.Put(uint32(0), ipUint32); err != nil {
		return fmt.Errorf("set egress IP: %w", err)
	}
	return nil
}

// GetPublicIP reads server egress IP from map.
func (x *XDPProgram) GetPublicIP() (net.IP, error) {
	if x == nil || x.serverEgressIPMap == nil {
		return nil, fmt.Errorf("eBPF program not loaded")
	}
	var ipUint32 uint32
	if err := x.serverEgressIPMap.Lookup(uint32(0), &ipUint32); err != nil {
		return nil, fmt.Errorf("get egress IP: %w", err)
	}
	return Uint32ToIP(ipUint32), nil
}

// SetVPNNetwork sets VPN network config in map.
func (x *XDPProgram) SetVPNNetwork(vpnNetwork string) error {
	if x == nil || x.vpnNetworkConfig == nil {
		return fmt.Errorf("XDP program not loaded")
	}
	network, mask, err := ParseCIDRToUint32(vpnNetwork)
	if err != nil {
		return fmt.Errorf("invalid VPN CIDR: %w", err)
	}
	if err := x.vpnNetworkConfig.Put(uint32(0), network); err != nil {
		return fmt.Errorf("set VPN network: %w", err)
	}
	if err := x.vpnNetworkConfig.Put(uint32(1), mask); err != nil {
		return fmt.Errorf("set VPN mask: %w", err)
	}
	return nil
}

// BlockIP blocks an IP in blocked_ips_map.
func (x *XDPProgram) BlockIP(ip net.IP, blockedUntil uint64) error {
	if x == nil || x.blockedIPs == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	ipUint32 := IPToUint32(ip)
	if ipUint32 == 0 {
		return fmt.Errorf("invalid IP address: %s", ip.String())
	}
	if err := x.blockedIPs.Put(ipUint32, blockedUntil); err != nil {
		return fmt.Errorf("block IP: %w", err)
	}
	return nil
}

// UnblockIP unblocks an IP.
func (x *XDPProgram) UnblockIP(ip net.IP) error {
	if x == nil || x.blockedIPs == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	ipUint32 := IPToUint32(ip)
	if ipUint32 == 0 {
		return fmt.Errorf("invalid IP address: %s", ip.String())
	}
	if err := x.blockedIPs.Delete(ipUint32); err != nil {
		return fmt.Errorf("unblock IP: %w", err)
	}
	return nil
}

// IsIPBlocked checks if IP is blocked.
func (x *XDPProgram) IsIPBlocked(ip net.IP) (bool, uint64, error) {
	if x == nil || x.blockedIPs == nil {
		return false, 0, fmt.Errorf("eBPF program not loaded")
	}
	ipUint32 := IPToUint32(ip)
	if ipUint32 == 0 {
		return false, 0, fmt.Errorf("invalid IP address: %s", ip.String())
	}
	var blockedUntil uint64
	if err := x.blockedIPs.Lookup(ipUint32, &blockedUntil); err != nil {
		return false, 0, nil
	}
	return true, blockedUntil, nil
}

// UpdateRateLimitConfig updates rate_limit_config_map.
func (x *XDPProgram) UpdateRateLimitConfig(config RateLimitConfig) error {
	if x == nil || x.rateLimitConfigMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}
	if err := x.rateLimitConfigMap.Put(uint32(0), config); err != nil {
		return fmt.Errorf("update rate limit config: %w", err)
	}
	return nil
}

// GetRateLimitConfig reads rate_limit_config_map.
func (x *XDPProgram) GetRateLimitConfig() (RateLimitConfig, error) {
	var config RateLimitConfig
	if x == nil || x.rateLimitConfigMap == nil {
		return config, fmt.Errorf("eBPF program not loaded")
	}
	if err := x.rateLimitConfigMap.Lookup(uint32(0), &config); err != nil {
		return config, fmt.Errorf("get rate limit config: %w", err)
	}
	return config, nil
}
