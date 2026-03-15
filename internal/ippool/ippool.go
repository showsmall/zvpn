package ippool

import (
	"fmt"
	"net"
	"sync"
)

// IPPool manages IP address allocation within a network
type IPPool struct {
	network *net.IPNet
	used   map[string]bool
	lock   sync.Mutex
}

// New creates a new IP pool for the given network
func New(network *net.IPNet) (*IPPool, error) {
	return &IPPool{
		network: network,
		used:   make(map[string]bool),
	}, nil
}

// Reserve marks an IP as used (e.g., gateway or existing allocations).
// Safe to call multiple times for the same IP.
func (p *IPPool) Reserve(ip net.IP) {
	if ip == nil {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.network.Contains(ip) {
		p.used[ip.String()] = true
	}
}

// Allocate returns an available IP from the pool
func (p *IPPool) Allocate() (net.IP, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	ip := make(net.IP, len(p.network.IP))
	copy(ip, p.network.IP)
	ip[len(ip)-1]++

	for {
		if !p.network.Contains(ip) {
			return nil, fmt.Errorf("IP pool exhausted")
		}

		ones, bits := p.network.Mask.Size()
		if ones < bits {
			broadcast := make(net.IP, len(ip))
			copy(broadcast, p.network.IP)
			for i := ones / 8; i < len(broadcast); i++ {
				if i == ones/8 {
					broadcast[i] |= ^p.network.Mask[i]
				} else {
					broadcast[i] = 255
				}
			}
			if ip.Equal(broadcast) {
				ip[len(ip)-1]++
				continue
			}
		}

		ipStr := ip.String()
		if !p.used[ipStr] {
			p.used[ipStr] = true
			return ip, nil
		}

		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] != 0 {
				break
			}
		}
	}
}

// Release returns an IP to the pool
func (p *IPPool) Release(ip net.IP) {
	p.lock.Lock()
	defer p.lock.Unlock()
	delete(p.used, ip.String())
}

// IsUsed returns true if the IP is currently allocated
func (p *IPPool) IsUsed(ip net.IP) bool {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.used[ip.String()]
}
