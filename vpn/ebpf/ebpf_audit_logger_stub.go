//go:build !linux || !ebpf
// +build !linux !ebpf

package ebpf

// StartAuditLoggerIfEnabled starts eBPF audit logger if eBPF is enabled
// Stub implementation when eBPF is not compiled
func StartAuditLoggerIfEnabled(xdpProgram *XDPProgram) {
	// No-op when eBPF is not compiled
}

// ClearEBPFAuditLogProtocolCache clears the cache to force reload on next access
// Stub implementation when eBPF is not compiled
func ClearEBPFAuditLogProtocolCache() {
	// No-op when eBPF is not compiled
}
