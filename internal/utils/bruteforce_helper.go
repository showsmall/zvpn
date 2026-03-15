package utils

import (
	"log"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/vpn/ebpf"
	"github.com/fisker/zvpn/vpn/security"
)

// BruteforceProtectionInitializer 帮助初始化 BruteforceProtection 实例
// 用于统一多个 handler 中的重复初始化逻辑
type BruteforceProtectionInitializer struct {
	cfg      *config.Config
	ebpfProg *ebpf.XDPProgram
}

// NewBruteforceProtectionInitializer 创建初始化器
func NewBruteforceProtectionInitializer(cfg *config.Config) *BruteforceProtectionInitializer {
	return &BruteforceProtectionInitializer{
		cfg: cfg,
	}
}

// SetEBPFProgram 设置 eBPF 程序（可选）
func (b *BruteforceProtectionInitializer) SetEBPFProgram(prog *ebpf.XDPProgram) {
	b.ebpfProg = prog
}

// Initialize 根据配置初始化 BruteforceProtection
// 如果配置中未启用，则返回 nil
func (b *BruteforceProtectionInitializer) Initialize(source string) *security.BruteforceProtection {
	if !b.cfg.VPN.EnableBruteforceProtection {
		return nil
	}

	maxAttempts := b.cfg.VPN.MaxLoginAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	lockoutDuration := time.Duration(b.cfg.VPN.LoginLockoutDuration) * time.Second
	if lockoutDuration <= 0 {
		lockoutDuration = 15 * time.Minute
	}

	windowDuration := time.Duration(b.cfg.VPN.LoginAttemptWindow) * time.Second
	if windowDuration <= 0 {
		windowDuration = 5 * time.Minute
	}

	bp := security.NewBruteforceProtection(maxAttempts, lockoutDuration, windowDuration)

	if b.ebpfProg != nil {
		bp.SetEBPFProgram(b.ebpfProg)
	}

	log.Printf("%s: Bruteforce protection initialized: max_attempts=%d, lockout=%v, window=%v, ebpf=%v",
		source, maxAttempts, lockoutDuration, windowDuration, b.ebpfProg != nil)

	return bp
}

// TryGetFromVPNServer 尝试从 VPNServer 获取已有的 BruteforceProtection 实例
// vpnServer 应该是 *vpnserver.VPNServer 类型（使用 interface 避免循环导入）
func TryGetBruteforceProtectionFromVPNServer(vpnServer interface{}) *security.BruteforceProtection {
	if vpnServer == nil {
		return nil
	}

	// 使用类型断言获取方法
	type bruteforceProvider interface {
		GetBruteforceProtection() interface{}
	}

	if provider, ok := vpnServer.(bruteforceProvider); ok {
		if bpInterface := provider.GetBruteforceProtection(); bpInterface != nil {
			if bp, ok := bpInterface.(*security.BruteforceProtection); ok {
				return bp
			}
		}
	}

	return nil
}

// TryGetEBPFProgramFromVPNServer 尝试从 VPNServer 获取 eBPF 程序
func TryGetEBPFProgramFromVPNServer(vpnServer interface{}) *ebpf.XDPProgram {
	if vpnServer == nil {
		return nil
	}

	type ebpfProvider interface {
		GetEBPFProgram() *ebpf.XDPProgram
	}

	if provider, ok := vpnServer.(ebpfProvider); ok {
		return provider.GetEBPFProgram()
	}

	return nil
}
