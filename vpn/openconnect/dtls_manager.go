package openconnect

import (
	"net"
	"sync"
	"time"
)

// DTLSClientManager 优化的 DTLS 客户端管理器
// 使用多重索引实现 O(1) 查找性能
type DTLSClientManager struct {
	mu sync.RWMutex

	// 主要存储: VPN IP -> DTLSClientInfo
	clientsByVPNIP map[string]*DTLSClientInfo

	// 索引1: UDP Addr (IP:Port) -> VPN IP
	// 用于快速查找基于 UDP 地址的客户端
	addrIndex map[string]string

	// 索引2: Source IP -> VPN IP
	// 用于从数据包的源 IP 查找客户端
	sourceIPIndex map[string]string
}

// NewDTLSClientManager 创建一个新的 DTLS 客户端管理器
func NewDTLSClientManager() *DTLSClientManager {
	return &DTLSClientManager{
		clientsByVPNIP: make(map[string]*DTLSClientInfo),
		addrIndex:      make(map[string]string),
		sourceIPIndex:  make(map[string]string),
	}
}

// Add 添加或更新客户端
func (m *DTLSClientManager) Add(vpnIP string, info *DTLSClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 如果客户端已存在，先删除旧索引
	if oldInfo, exists := m.clientsByVPNIP[vpnIP]; exists {
		m.removeIndexes(vpnIP, oldInfo)
	}

	// 添加新客户端
	m.clientsByVPNIP[vpnIP] = info

	// 更新索引
	m.addIndexes(vpnIP, info)
}

// Remove 移除客户端
func (m *DTLSClientManager) Remove(vpnIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if info, exists := m.clientsByVPNIP[vpnIP]; exists {
		m.removeIndexes(vpnIP, info)
		delete(m.clientsByVPNIP, vpnIP)
	}
}

// GetByVPNIP 通过 VPN IP 获取客户端 - O(1)
func (m *DTLSClientManager) GetByVPNIP(vpnIP string) (*DTLSClientInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, exists := m.clientsByVPNIP[vpnIP]
	if exists && info != nil {
		info.LastSeen = time.Now()
	}
	return info, exists
}

// GetByAddr 通过 UDP 地址获取客户端 - O(1)
func (m *DTLSClientManager) GetByAddr(addr *net.UDPAddr) (*DTLSClientInfo, string, bool) {
	if addr == nil {
		return nil, "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := addr.String()
	vpnIP, exists := m.addrIndex[key]
	if !exists {
		return nil, "", false
	}

	info, exists := m.clientsByVPNIP[vpnIP]
	if exists && info != nil {
		info.LastSeen = time.Now()
	}
	return info, vpnIP, exists
}

// GetBySourceIP 通过源 IP 获取客户端 - O(1)
func (m *DTLSClientManager) GetBySourceIP(srcIP net.IP) (*DTLSClientInfo, string, bool) {
	if srcIP == nil {
		return nil, "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := srcIP.String()
	vpnIP, exists := m.sourceIPIndex[key]
	if !exists {
		return nil, "", false
	}

	info, exists := m.clientsByVPNIP[vpnIP]
	if exists && info != nil {
		info.LastSeen = time.Now()
	}
	return info, vpnIP, exists
}

// UpdateAddr 更新客户端的 UDP 地址
func (m *DTLSClientManager) UpdateAddr(vpnIP string, newAddr *net.UDPAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.clientsByVPNIP[vpnIP]
	if !exists || info == nil {
		return
	}

	// 删除旧地址索引
	if info.UDPAddr != nil {
		delete(m.addrIndex, info.UDPAddr.String())
	}

	// 更新地址
	info.UDPAddr = newAddr
	info.LastSeen = time.Now()

	// 添加新地址索引
	if newAddr != nil {
		m.addrIndex[newAddr.String()] = vpnIP
	}
}

// GetClientCount 获取客户端数量
func (m *DTLSClientManager) GetClientCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clientsByVPNIP)
}

// GetAllClients 获取所有客户端（用于日志等）
func (m *DTLSClientManager) GetAllClients() map[string]*DTLSClientInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 返回副本以避免外部修改
	result := make(map[string]*DTLSClientInfo, len(m.clientsByVPNIP))
	for k, v := range m.clientsByVPNIP {
		result[k] = v
	}
	return result
}

// addIndexes 添加索引
func (m *DTLSClientManager) addIndexes(vpnIP string, info *DTLSClientInfo) {
	if info.UDPAddr != nil {
		m.addrIndex[info.UDPAddr.String()] = vpnIP
	}
	if info.Client != nil && info.Client.IP != nil {
		m.sourceIPIndex[info.Client.IP.String()] = vpnIP
	}
}

// removeIndexes 移除索引
func (m *DTLSClientManager) removeIndexes(vpnIP string, info *DTLSClientInfo) {
	if info.UDPAddr != nil {
		delete(m.addrIndex, info.UDPAddr.String())
	}
	if info.Client != nil && info.Client.IP != nil {
		delete(m.sourceIPIndex, info.Client.IP.String())
	}
}

// LegacyCompatibility 为兼容旧代码提供的方法
// 以下方法保持与旧代码的兼容性

// GetClientsMap 返回客户端 map（用于向后兼容）
func (m *DTLSClientManager) GetClientsMap() map[string]*DTLSClientInfo {
	return m.GetAllClients()
}
