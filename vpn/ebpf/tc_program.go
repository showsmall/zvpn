package ebpf

import (
	"fmt"
	"net"
)

// TCNATProgram is the stable interface used by upper layers.
// Build-tag specific implementations stay inside the ebpf package.
type TCNATProgram interface {
	SetPublicIP(publicIP net.IP) error
	SetVPNNetwork(vpnNetwork string) error
	AddVPNClient(vpnIP, clientIP net.IP) error
	RemoveVPNClient(vpnIP net.IP) error
	GetNATStats() (map[uint32]uint64, error)
	Close() error
}

// LoadTCNATProgram loads and configures the TC NAT program.
func LoadTCNATProgram(ifName string, publicIP net.IP, vpnNetwork string) (TCNATProgram, error) {
	tcProg, err := LoadTCProgram(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF TC program: %w", err)
	}

	if err := tcProg.SetVPNNetwork(vpnNetwork); err != nil {
		tcProg.Close()
		return nil, fmt.Errorf("failed to set VPN network in TC program: %w", err)
	}

	if publicIP != nil {
		if err := tcProg.SetPublicIP(publicIP); err != nil {
			tcProg.Close()
			return nil, fmt.Errorf("failed to set public IP in TC program: %w", err)
		}
	}

	return tcProg, nil
}
