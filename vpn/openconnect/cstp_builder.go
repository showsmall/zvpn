package openconnect

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/models"
)

// CSTPConfigBuilder 用于构建 CSTP 配置响应
type CSTPConfigBuilder struct {
	config          *config.Config
	responseBuilder strings.Builder
	user            *models.User
	tunnelMode      string
	netmask         string
	isMobile        bool
}

// NewCSTPConfigBuilder 创建一个新的配置构建器
func NewCSTPConfigBuilder(cfg *config.Config, user *models.User, tunnelMode, netmask string, isMobile bool) *CSTPConfigBuilder {
	return &CSTPConfigBuilder{
		config:     cfg,
		user:       user,
		tunnelMode: tunnelMode,
		netmask:    netmask,
		isMobile:   isMobile,
	}
}

// BuildBasicHeaders 构建基本 HTTP 响应头
func (b *CSTPConfigBuilder) BuildBasicHeaders(hostname string) {
	b.responseBuilder.WriteString("HTTP/1.1 200 OK\r\n")
	b.responseBuilder.WriteString("Content-Type: application/octet-stream\r\n")
	b.responseBuilder.WriteString("Connection: keep-alive\r\n")
	b.responseBuilder.WriteString("Server: ZVPN 1.0\r\n")
	b.responseBuilder.WriteString("X-CSTP-Version: 1\r\n")
	b.responseBuilder.WriteString("X-CSTP-Server-Name: ZVPN 1.0\r\n")
	b.responseBuilder.WriteString("X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.\r\n")
	b.responseBuilder.WriteString("X-CSTP-Address: " + b.user.VPNIP + "\r\n")
	b.responseBuilder.WriteString("X-CSTP-Netmask: " + b.netmask + "\r\n")
	b.responseBuilder.WriteString("X-CSTP-Hostname: " + hostname + "\r\n")
}

// AddCompressionHeaders 添加压缩相关的响应头
func (b *CSTPConfigBuilder) AddCompressionHeaders(cstpAcceptEncoding, dtlsAcceptEncoding string) {
	if !b.config.VPN.EnableCompression {
		return
	}

	compressionType := getCompressionType(b.config)
	if compressionType == "none" {
		return
	}

	lowerType := strings.ToLower(compressionType)

	if cstpAcceptEncoding != "" && strings.Contains(strings.ToLower(cstpAcceptEncoding), lowerType) {
		b.responseBuilder.WriteString("X-CSTP-Content-Encoding: " + compressionType + "\r\n")
	}

	if dtlsAcceptEncoding != "" && strings.Contains(strings.ToLower(dtlsAcceptEncoding), lowerType) {
		b.responseBuilder.WriteString("X-DTLS-Content-Encoding: " + compressionType + "\r\n")
	}
}

// AddMTUHeader 添加 MTU 相关的响应头
func (b *CSTPConfigBuilder) AddMTUHeader(mtu int) {
	b.responseBuilder.WriteString("X-CSTP-Base-MTU: " + intToStr(mtu) + "\r\n")
	b.responseBuilder.WriteString("X-CSTP-MTU: " + intToStr(mtu) + "\r\n")
	if b.config.VPN.EnableDTLS {
		b.responseBuilder.WriteString("X-DTLS-MTU: " + intToStr(mtu) + "\r\n")
	}
}

// AddKeepaliveHeaders 添加保活相关的响应头
func (b *CSTPConfigBuilder) AddKeepaliveHeaders(cstpDPD, cstpKeepalive int) {
	b.responseBuilder.WriteString("X-CSTP-DPD: " + intToStr(cstpDPD) + "\r\n")
	b.responseBuilder.WriteString("X-CSTP-Keepalive: " + intToStr(cstpKeepalive) + "\r\n")
}

// AddDTLSHeaders 添加 DTLS 相关的响应头
func (b *CSTPConfigBuilder) AddDTLSHeaders(dtlsSessionID, dtlsPort, dtlsDPDStr, dtlsKeepaliveStr, cipherSuiteHeader string) {
	if !b.config.VPN.EnableDTLS {
		return
	}

	b.responseBuilder.WriteString("X-DTLS-Session-ID: " + dtlsSessionID + "\r\n")
	b.responseBuilder.WriteString("X-DTLS-Port: " + dtlsPort + "\r\n")
	b.responseBuilder.WriteString("X-DTLS-DPD: " + dtlsDPDStr + "\r\n")
	b.responseBuilder.WriteString("X-DTLS-Keepalive: " + dtlsKeepaliveStr + "\r\n")
	b.responseBuilder.WriteString("X-DTLS12-CipherSuite: " + cipherSuiteHeader + "\r\n")
	b.responseBuilder.WriteString("X-DTLS-Rekey-Time: 86400\r\n")
	b.responseBuilder.WriteString("X-DTLS-Rekey-Method: new-tunnel\r\n")
}

// AddDNSHeaders 添加 DNS 服务器相关的响应头
func (b *CSTPConfigBuilder) AddDNSHeaders(dnsServers []string) bool {
	hasDNS := false
	for _, dns := range dnsServers {
		if dns == "" {
			continue
		}
		dns = strings.TrimSpace(dns)
		if ip := net.ParseIP(dns); ip != nil {
			b.responseBuilder.WriteString("X-CSTP-DNS: " + dns + "\r\n")
			hasDNS = true
		}
	}
	return hasDNS
}

// AddSplitDNSHeaders 添加 Split-DNS 相关的响应头
func (b *CSTPConfigBuilder) AddSplitDNSHeaders(splitDNSDomains []string) {
	for _, domain := range splitDNSDomains {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			b.responseBuilder.WriteString("X-CSTP-Split-DNS: " + domain + "\r\n")
		}
	}
}

// AddRouteHeaders 添加路由相关的响应头
func (b *CSTPConfigBuilder) AddRouteHeaders(splitIncludeRoutes, splitExcludeRoutes []string) {
	if b.tunnelMode != "full" && len(splitIncludeRoutes) > 0 {
		optimizedRoutes := optimizeRoutes(splitIncludeRoutes)
		for _, route := range optimizedRoutes {
			routeFormatted := convertCIDRToSubnetMask(route)
			b.responseBuilder.WriteString("X-CSTP-Split-Include: " + routeFormatted + "\r\n")
		}
	}

	if b.tunnelMode == "full" && len(splitExcludeRoutes) > 0 {
		optimizedExcludeRoutes := optimizeRoutes(splitExcludeRoutes)
		for _, route := range optimizedExcludeRoutes {
			routeFormatted := convertCIDRToSubnetMask(route)
			b.responseBuilder.WriteString("X-CSTP-Split-Exclude: " + routeFormatted + "\r\n")
		}
	}
}

// AddFixedHeaders 添加固定的响应头
func (b *CSTPConfigBuilder) AddFixedHeaders(tunnelAllDNS bool) {
	b.responseBuilder.WriteString("X-CSTP-Lease-Duration: 1209600\r\n")
	b.responseBuilder.WriteString("X-CSTP-Session-Timeout: none\r\n")
	b.responseBuilder.WriteString("X-CSTP-Session-Timeout-Alert-Interval: 60\r\n")
	b.responseBuilder.WriteString("X-CSTP-Session-Timeout-Remaining: none\r\n")
	b.responseBuilder.WriteString("X-CSTP-Idle-Timeout: 18000\r\n")
	b.responseBuilder.WriteString("X-CSTP-Disconnected-Timeout: 18000\r\n")
	b.responseBuilder.WriteString("X-CSTP-Keep: true\r\n")
	b.responseBuilder.WriteString("X-CSTP-Tunnel-All-DNS: " + strconv.FormatBool(tunnelAllDNS) + "\r\n")
	b.responseBuilder.WriteString("X-CSTP-Rekey-Time: 86400\r\n")
	b.responseBuilder.WriteString("X-CSTP-Rekey-Method: new-tunnel\r\n")
	b.responseBuilder.WriteString("X-CSTP-MSIE-Proxy-Lockdown: true\r\n")
	b.responseBuilder.WriteString("X-CSTP-Smartcard-Removal-Disconnect: true\r\n")
	b.responseBuilder.WriteString("X-CSTP-Routing-Filtering-Ignore: false\r\n")
	b.responseBuilder.WriteString("X-CSTP-Quarantine: false\r\n")
	b.responseBuilder.WriteString("X-CSTP-Disable-Always-On-VPN: false\r\n")
	b.responseBuilder.WriteString("X-CSTP-Client-Bypass-Protocol: true\r\n")
	b.responseBuilder.WriteString("X-CSTP-TCP-Keepalive: false\r\n")
	b.responseBuilder.WriteString("X-Cisco-Client-Compat: 1\r\n")
	b.responseBuilder.WriteString("\r\n")
}

// String 返回构建的响应字符串
func (b *CSTPConfigBuilder) String() string {
	return b.responseBuilder.String()
}

// intToStr 将 int 转换为 string
func intToStr(i int) string {
	return strconv.Itoa(i)
}

// DTLSSessionConfig DTLS 会话配置
type DTLSSessionConfig struct {
	SessionID         string
	Port              string
	DPDStr            string
	KeepaliveStr      string
	CipherSuiteHeader string
}

// MobileConfig 移动端配置
type MobileConfig struct {
	IsMobile  bool
	DPD       int
	Keepalive int
}

// CalculateMobileConfig 计算移动端配置
func CalculateMobileConfig(cfg *config.Config, isMobile bool) MobileConfig {
	mc := MobileConfig{IsMobile: isMobile}
	if isMobile {
		mc.DPD = cfg.VPN.MobileDPD
		mc.Keepalive = cfg.VPN.MobileKeepalive
		if mc.DPD == 0 {
			mc.DPD = 60
		}
		if mc.Keepalive == 0 {
			mc.Keepalive = 4
		}
	} else {
		mc.DPD = cfg.VPN.CSTPDPD
		mc.Keepalive = cfg.VPN.CSTPKeepalive
		if mc.DPD == 0 {
			mc.DPD = 30
		}
		if mc.Keepalive == 0 {
			mc.Keepalive = 20
		}
	}
	return mc
}

// RouteConfig 路由配置
type RouteConfig struct {
	IncludeRoutes []string
	ExcludeRoutes []string
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
}

