//go:build linux && ebpf
// +build linux,ebpf

package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// XDPProgram holds loaded XDP objects and map references.
// C为主、Go只负责装载和map操作. Map ops in xdp_maps.go.
type XDPProgram struct {
	objs               *xdpObjects
	link               link.Link
	ifName             string
	policiesMap        *ebpf.Map
	policyChains       *ebpf.Map
	vpnClients         *ebpf.Map
	stats              *ebpf.Map
	policyStats        *ebpf.Map
	policyEvents       *ebpf.Map
	blockedIPs         *ebpf.Map
	rateLimitConfigMap *ebpf.Map
	serverEgressIPMap  *ebpf.Map
	vpnNetworkConfig   *ebpf.Map
	policyChainStatus  *ebpf.Map
}

// LoadXDPProgram loads and attaches the XDP program. Map operations are in xdp_maps.go.
func LoadXDPProgram(ifName string) (*XDPProgram, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	objs := &xdpObjects{}
	if err := loadXdpObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to find interface %s: %w", ifName, err)
	}

	opts := link.XDPOptions{
		Program:   objs.XdpVpnForward,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	}

	xdpLink, err := link.AttachXDP(opts)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// Initialize policy chain status (optimization: C checks this before traversing chain)
	for hookPoint := uint32(0); hookPoint < 5; hookPoint++ {
		if err := objs.PolicyChainStatus.Put(hookPoint, uint8(0)); err != nil {
			objs.Close()
			return nil, fmt.Errorf("failed to initialize policy chain status: %w", err)
		}
	}

	return &XDPProgram{
		objs:               objs,
		link:               xdpLink,
		ifName:             ifName,
		policiesMap:        objs.Policies,
		policyChains:       objs.PolicyChains,
		vpnClients:         objs.VpnClients,
		stats:              objs.Stats,
		policyStats:        objs.PolicyStats,
		policyEvents:       objs.PolicyEvents,
		blockedIPs:         objs.BlockedIpsMap,
		rateLimitConfigMap: objs.RateLimitConfigMap,
		serverEgressIPMap:  objs.ServerEgressIp,
		vpnNetworkConfig:   objs.VpnNetworkConfig,
		policyChainStatus:  objs.PolicyChainStatus,
	}, nil
}

// Close detaches and closes the XDP program.
func (x *XDPProgram) Close() error {
	var errs []error
	if x.link != nil {
		if err := x.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close XDP link: %w", err))
		}
	}
	if x.objs != nil {
		if err := x.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close eBPF objects: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}
	return nil
}
