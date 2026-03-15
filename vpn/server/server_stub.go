//go:build !linux

package server

import (
	"github.com/fisker/zvpn/vpn/ebpf"
)

// ============================================================================
// Platform Stubs (Non-Linux platforms)
// ============================================================================

// getBatchListener returns nil on non-Linux platforms
func getBatchListener() func(*VPNServer, *TUNDevice) {
	return nil
}

// getAFXDPListener returns nil for non-Linux platforms
func getAFXDPListener() func(*VPNServer, *ebpf.XDPSocket) {
	return nil
}
