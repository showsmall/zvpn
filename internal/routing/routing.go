package routing

import (
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Manager manages network routes via netlink
type Manager struct {
	interfaceName string
}

// New creates a new route manager for the given interface
func New(interfaceName string) *Manager {
	return &Manager{
		interfaceName: interfaceName,
	}
}

// AddRoute adds a route using netlink
func (rm *Manager) AddRoute(network *net.IPNet, gateway net.IP, metric int) error {
	link, err := netlink.LinkByName(rm.interfaceName)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", rm.interfaceName, err)
	}
	route := &netlink.Route{
		Dst:       network,
		Gw:        gateway,
		LinkIndex: link.Attrs().Index,
		Priority:  metric,
	}
	if err := netlink.RouteAdd(route); err != nil {
		if errno, ok := err.(syscall.Errno); !ok || errno != syscall.EEXIST {
			return fmt.Errorf("add route %s via %s: %w", network.String(), gateway.String(), err)
		}
	}
	return nil
}

// DeleteRoute deletes a route using netlink
func (rm *Manager) DeleteRoute(network *net.IPNet) error {
	link, err := netlink.LinkByName(rm.interfaceName)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", rm.interfaceName, err)
	}
	routes, err := netlink.RouteList(link, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == network.String() {
			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("delete route %s: %w", network.String(), err)
			}
			return nil
		}
	}
	return nil
}

// ParseCIDR parses a CIDR string and returns an IPNet. Adds /32 for single IPs.
func ParseCIDR(cidr string) (*net.IPNet, error) {
	if !strings.Contains(cidr, "/") {
		cidr = cidr + "/32"
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	return ipNet, err
}

// CreateAndConfigureTUN is deprecated
func (rm *Manager) CreateAndConfigureTUN() error {
	log.Printf("Note: CreateAndConfigureTUN is deprecated, TUN device management moved to VPNServer")
	return nil
}

// GetEgressInterfaceIP returns the IP of the egress interface for the default route
func GetEgressInterfaceIP() (net.IP, error) {
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	var defaultRoute *netlink.Route
	for i := range routes {
		if routes[i].Dst == nil {
			defaultRoute = &routes[i]
			break
		}
	}
	if defaultRoute == nil {
		return nil, fmt.Errorf("default route not found")
	}

	var link netlink.Link
	if defaultRoute.LinkIndex > 0 {
		link, err = netlink.LinkByIndex(defaultRoute.LinkIndex)
		if err != nil {
			return nil, fmt.Errorf("get egress interface: %w", err)
		}
	} else if defaultRoute.Gw != nil {
		link, err = findInterfaceForGateway(defaultRoute.Gw)
		if err != nil {
			return nil, fmt.Errorf("find interface for gateway: %w", err)
		}
	} else {
		return nil, fmt.Errorf("default route has no interface or gateway")
	}

	addrs, err := netlink.AddrList(link, 0)
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	for _, addr := range addrs {
		if addr.IP.IsLoopback() || addr.IP.IsLinkLocalUnicast() {
			continue
		}
		if addr.IP.To4() != nil {
			return addr.IP, nil
		}
	}
	if len(addrs) > 0 {
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				return addr.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 on egress interface %s", link.Attrs().Name)
}

func findInterfaceForGateway(gateway net.IP) (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route.Gw != nil && route.Gw.Equal(gateway) && route.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err == nil {
				return link, nil
			}
		}
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, 0)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr.IPNet != nil && addr.IPNet.Contains(gateway) {
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface for gateway %s", gateway.String())
}
