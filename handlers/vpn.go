package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/internal/compression"
	"github.com/fisker/zvpn/internal/database"
	"github.com/fisker/zvpn/models"
	vpnserver "github.com/fisker/zvpn/vpn/server"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	defaultEnableCompression = false
	defaultCompressionType   = "lz4"
)

type xdpStatsReader interface {
	GetDetailedStats() (uint64, uint64, error)
	GetStats() (uint64, error)
}

type tcStatsReader interface {
	GetNATStats() (map[uint32]uint64, error)
}

type ebpfStatsResponse struct {
	EBPFEnabled                      bool   `json:"ebpf_enabled"`
	TotalPackets                     uint64 `json:"total_packets"`
	DroppedPackets                   uint64 `json:"dropped_packets"`
	TCNATPerformedPackets            uint64 `json:"tc_nat_performed_packets"`
	TCTotalPackets                   uint64 `json:"tc_total_packets"`
	TCVPNNetworkNotConfiguredPackets uint64 `json:"tc_vpn_network_not_configured_packets"`
	Timestamp                        int64  `json:"timestamp,omitempty"`
}

type VPNHandler struct {
	config                *config.Config
	vpnServer             *vpnserver.VPNServer
	statsReaderOverride   xdpStatsReader
	tcStatsReaderOverride tcStatsReader
}

func NewVPNHandler(cfg *config.Config) *VPNHandler {
	h := &VPNHandler{config: cfg}
	h.config.VPN.EnableCompression = defaultEnableCompression
	h.config.VPN.CompressionType = defaultCompressionType
	h.loadCompressionFromDB()
	return h
}

func (h *VPNHandler) SetVPNServer(server *vpnserver.VPNServer) {
	h.vpnServer = server
	h.applyCompressionToRuntime()
}

func collectEBPFStats(xdpProg xdpStatsReader) ebpfStatsResponse {
	stats := ebpfStatsResponse{}
	if xdpProg == nil {
		return stats
	}

	stats.EBPFEnabled = true

	total, dropped, err := xdpProg.GetDetailedStats()
	if err == nil {
		stats.TotalPackets = total
		stats.DroppedPackets = dropped
		return stats
	}

	log.Printf("Warning: Failed to get detailed eBPF stats: %v, trying basic stats", err)
	packets, basicErr := xdpProg.GetStats()
	if basicErr != nil {
		log.Printf("Warning: Failed to get basic eBPF stats: %v (but eBPF is still enabled)", basicErr)
		return stats
	}

	stats.TotalPackets = packets
	return stats
}

func collectTCStats(tcProg tcStatsReader, stats *ebpfStatsResponse) {
	if tcProg == nil {
		return
	}

	natStats, err := tcProg.GetNATStats()
	if err != nil {
		return
	}

	stats.EBPFEnabled = true
	stats.TCNATPerformedPackets = natStats[0]
	stats.TCTotalPackets = natStats[4]
	stats.TCVPNNetworkNotConfiguredPackets = natStats[5]
}

func (h *VPNHandler) getEBPFStatsSnapshot() ebpfStatsResponse {
	if h.statsReaderOverride != nil || h.tcStatsReaderOverride != nil {
		stats := collectEBPFStats(h.statsReaderOverride)
		collectTCStats(h.tcStatsReaderOverride, &stats)
		return stats
	}

	if h.vpnServer == nil {
		log.Printf("VPN server is nil")
		return ebpfStatsResponse{}
	}

	stats := collectEBPFStats(h.vpnServer.GetEBPFProgram())
	if natStats, err := h.vpnServer.GetTCNATStats(); err == nil {
		stats.EBPFEnabled = true
		stats.TCNATPerformedPackets = natStats[0]
		stats.TCTotalPackets = natStats[4]
		stats.TCVPNNetworkNotConfiguredPackets = natStats[5]
	}

	return stats
}

func (h *VPNHandler) writeEBPFStatsEvent(c *gin.Context, timestamp int64) {
	stats := h.getEBPFStatsSnapshot()
	stats.Timestamp = timestamp
	c.SSEvent("stats", stats)
}

type ConnectRequest struct {
	Token string `json:"token" binding:"required"` // JWT token for authentication
}

type ConnectResponse struct {
	Success      bool       `json:"success"`
	Message      string     `json:"message"`
	ConnectionID string     `json:"connection_id,omitempty"`
	Config       *VPNConfig `json:"config,omitempty"`
}

type VPNConfig struct {
	VPNIP      string   `json:"vpn_ip"`      // Assigned VPN IP (e.g., 10.8.0.2)
	VPNNetwork string   `json:"vpn_network"` // VPN network (e.g., 10.8.0.0/24)
	Gateway    string   `json:"gateway"`     // VPN gateway (e.g., 10.8.0.1)
	ServerIP   string   `json:"server_ip"`   // VPN server IP
	ServerPort int      `json:"server_port"` // VPN server port
	Routes     []string `json:"routes"`      // Routes to access via VPN
	MTU        int      `json:"mtu"`         // MTU size
}

type ConnectionStatus struct {
	Connected   bool       `json:"connected"`
	VPNIP       string     `json:"vpn_ip,omitempty"`
	ConnectedAt time.Time  `json:"connected_at,omitempty"`
	Config      *VPNConfig `json:"config,omitempty"`
}

func (h *VPNHandler) Connect(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user models.User
	if err := database.DB.Preload("Policy").Preload("Policy.Routes").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "您的账户已被禁用，无法连接VPN。请联系管理员激活账户。"})
		return
	}

	if user.Connected {
		if !h.config.VPN.AllowMultiClientLogin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Multi-client login disabled, user already connected"})
			return
		}
		config := h.buildVPNConfig(&user)
		c.JSON(http.StatusOK, ConnectResponse{
			Success: true,
			Message: "Already connected",
			Config:  config,
		})
		return
	}

	if h.vpnServer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VPN server not initialized"})
		return
	}
	vpnIP, err := h.vpnServer.AllocateVPNIP()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to allocate VPN IP"})
		return
	}

	user.VPNIP = vpnIP.String()
	user.Connected = true
	if err := database.DB.Model(&user).Select("vpn_ip", "connected", "updated_at").Updates(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user"})
		return
	}

	if h.vpnServer != nil {
		clientIP := c.ClientIP()
		if clientIP != "" {
			realIP := net.ParseIP(clientIP)
			if h.vpnServer.GetEBPFProgram() != nil {
				if err := h.vpnServer.GetEBPFProgram().AddVPNClient(vpnIP, realIP); err != nil {
					fmt.Printf("Warning: Failed to add client to eBPF map: %v\n", err)
				}
			}
		}

		if err := h.vpnServer.CreatePolicyHooks(&user); err != nil {
			fmt.Printf("Warning: Failed to create policy hooks: %v\n", err)
		}
	}

	config := h.buildVPNConfig(&user)

	connectionID := fmt.Sprintf("%d-%d", user.ID, time.Now().Unix())

	c.JSON(http.StatusOK, ConnectResponse{
		Success:      true,
		Message:      "Connected successfully",
		ConnectionID: connectionID,
		Config:       config,
	})
}

func (h *VPNHandler) Disconnect(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.Connected {
		c.JSON(http.StatusOK, gin.H{"message": "Not connected"})
		return
	}

	if h.vpnServer != nil && user.VPNIP != "" {
		vpnIP := net.ParseIP(user.VPNIP)
		if vpnIP != nil && h.vpnServer.GetEBPFProgram() != nil {
			if err := h.vpnServer.GetEBPFProgram().RemoveVPNClient(vpnIP); err != nil {
				fmt.Printf("Warning: Failed to remove client from eBPF map: %v\n", err)
			}
		}

		if err := h.vpnServer.RemovePolicyHooks(user.ID); err != nil {
			fmt.Printf("Warning: Failed to remove policy hooks: %v\n", err)
		}
	}

	user.Connected = false
	releaseIP := user.VPNIP
	user.VPNIP = ""
	if err := database.DB.Model(&user).Select("connected", "vpn_ip", "updated_at").Updates(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	if h.vpnServer != nil && releaseIP != "" {
		if ip := net.ParseIP(releaseIP); ip != nil {
			h.vpnServer.ReleaseVPNIP(ip)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Disconnected successfully",
	})
}

func (h *VPNHandler) GetConnectionStatus(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user models.User
	if err := database.DB.Preload("Policy").Preload("Policy.Routes").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	status := ConnectionStatus{
		Connected: user.Connected,
		VPNIP:     user.VPNIP,
	}

	if user.Connected {
		status.Config = h.buildVPNConfig(&user)
		status.ConnectedAt = user.UpdatedAt
	}

	c.JSON(http.StatusOK, status)
}

func (h *VPNHandler) GetConfig(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user models.User
	if err := database.DB.Preload("Policy").Preload("Policy.Routes").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.Connected {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not connected to VPN"})
		return
	}

	config := h.buildVPNConfig(&user)
	c.JSON(http.StatusOK, config)
}

func (h *VPNHandler) buildVPNConfig(user *models.User) *VPNConfig {
	_, vpnNet, _ := net.ParseCIDR(h.config.VPN.Network)
	gateway := make(net.IP, len(vpnNet.IP))
	copy(gateway, vpnNet.IP)
	gateway[len(gateway)-1]++ // First usable IP

	var routes []string
	if user.PolicyID != 0 && len(user.Policy.Routes) > 0 {
		for _, route := range user.Policy.Routes {
			routes = append(routes, route.Network)
		}
	}

	serverIP := h.config.Server.Host
	if serverIP == "0.0.0.0" {
		serverIP = "localhost" // Default for development
	}

	customPort, err := strconv.Atoi(h.config.VPN.CustomPort)
	if err != nil {
		customPort = 443 // fallback if config value malformed
	}

	return &VPNConfig{
		VPNIP:      user.VPNIP,
		VPNNetwork: h.config.VPN.Network,
		Gateway:    gateway.String(),
		ServerIP:   serverIP,
		ServerPort: customPort,
		Routes:     routes,
		MTU:        h.config.VPN.MTU,
	}
}

func (h *VPNHandler) GetStatus(c *gin.Context) {
	var connectedUsers int64
	database.DB.Model(&models.User{}).Where("connected = ?", true).Count(&connectedUsers)

	var totalUsers int64
	database.DB.Model(&models.User{}).Count(&totalUsers)

	var totalPolicies int64
	database.DB.Model(&models.Policy{}).Count(&totalPolicies)

	var vpnPort int
	if h.config.VPN.EnableOpenConnect {
		if port, err := strconv.Atoi(h.config.VPN.OpenConnectPort); err == nil {
			vpnPort = port
		}
	} else if h.config.VPN.EnableCustomProtocol {
		if port, err := strconv.Atoi(h.config.VPN.CustomPort); err == nil {
			vpnPort = port
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"connected_users": connectedUsers,
		"total_users":     totalUsers,
		"total_policies":  totalPolicies,
		"vpn_network":     h.config.VPN.Network,
		"vpn_port":        vpnPort,
	})
}

type ConnectedUserResponse struct {
	ID          uint       `json:"id"`
	Username    string     `json:"username"`
	FullName    string     `json:"full_name,omitempty"` // 中文名/全名（LDAP用户有，系统账户可选）
	VPNIP       string     `json:"vpn_ip"`
	Connected   bool       `json:"connected"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	UserAgent   string     `json:"user_agent,omitempty"`
	ClientOS    string     `json:"client_os,omitempty"`
	ClientVer   string     `json:"client_ver,omitempty"`
	Groups      []struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	} `json:"groups,omitempty"`
}

func (h *VPNHandler) GetConnectedUsers(c *gin.Context) {
	var users []models.User
	if err := database.DB.Where("connected = ?", true).Preload("Groups").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]ConnectedUserResponse, len(users))
	for i, user := range users {
		var connectedAt *time.Time
		if user.LastSeen != nil {
			connectedAt = user.LastSeen
		} else {
			connectedAt = &user.UpdatedAt
		}

		response[i] = ConnectedUserResponse{
			ID:          user.ID,
			Username:    user.Username,
			FullName:    user.FullName,
			VPNIP:       user.VPNIP,
			Connected:   user.Connected,
			ConnectedAt: connectedAt,
		}

		if h.vpnServer != nil {
			if client, ok := h.vpnServer.GetClient(user.ID); ok && client != nil {
				response[i].UserAgent = client.UserAgent
				response[i].ClientOS = client.ClientOS
				response[i].ClientVer = client.ClientVer
			}
		}

		if len(user.Groups) > 0 {
			response[i].Groups = make([]struct {
				ID   uint   `json:"id"`
				Name string `json:"name"`
			}, len(user.Groups))
			for j, group := range user.Groups {
				response[i].Groups[j] = struct {
					ID   uint   `json:"id"`
					Name string `json:"name"`
				}{
					ID:   group.ID,
					Name: group.Name,
				}
			}
		}
	}

	c.JSON(http.StatusOK, response)
}

func (h *VPNHandler) GetEBPFStats(c *gin.Context) {
	c.JSON(http.StatusOK, h.getEBPFStatsSnapshot())
}

func (h *VPNHandler) StreamEBPFStats(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")          // Disable nginx buffering
	c.Header("Access-Control-Allow-Origin", "*") // Allow CORS for SSE
	c.Header("Access-Control-Allow-Credentials", "true")

	clientGone := c.Request.Context().Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	c.SSEvent("connected", gin.H{"message": "Connected to eBPF stats stream"})
	c.Writer.Flush()

	for {
		select {
		case <-clientGone:
			return
		case <-ticker.C:
			h.writeEBPFStatsEvent(c, time.Now().Unix())
			c.Writer.Flush()
		}
	}
}

func (h *VPNHandler) GetAdminConfig(c *gin.Context) {
	config := gin.H{
		"enable_compression": h.config.VPN.EnableCompression,
		"compression_type":   h.config.VPN.CompressionType,
	}

	c.JSON(http.StatusOK, config)
}

type CompressionConfigRequest struct {
	EnableCompression bool   `json:"enable_compression" binding:"required"`
	CompressionType   string `json:"compression_type" binding:"required,oneof=none lz4 gzip"`
}

func (h *VPNHandler) UpdateCompressionConfig(c *gin.Context) {
	var req CompressionConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.saveCompressionToDB(&req); err != nil {
		log.Printf("Failed to persist compression settings: %v", err)
	}

	h.config.VPN.EnableCompression = req.EnableCompression
	h.config.VPN.CompressionType = req.CompressionType

	if h.vpnServer != nil {
		compressionType := compression.CompressionType(req.CompressionType)
		if req.EnableCompression && compressionType != compression.CompressionNone {
			h.vpnServer.CompressionMgr = compression.NewCompressionManager(compressionType)
		} else {
			h.vpnServer.CompressionMgr = compression.NewCompressionManager(compression.CompressionNone)
		}
	}

	config := gin.H{
		"enable_compression": h.config.VPN.EnableCompression,
		"compression_type":   h.config.VPN.CompressionType,
	}

	c.JSON(http.StatusOK, config)
}

const compressionSettingKey = "compression_settings"

func (h *VPNHandler) saveCompressionToDB(req *CompressionConfigRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemSetting{Key: compressionSettingKey, Value: string(data)}).Error
}

func (h *VPNHandler) loadCompressionFromDB() {
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", compressionSettingKey).First(&setting).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Printf("Failed to load compression settings from DB: %v", err)
		}
		h.config.VPN.EnableCompression = defaultEnableCompression
		h.config.VPN.CompressionType = defaultCompressionType
		return
	}
	var cfg CompressionConfigRequest
	if err := json.Unmarshal([]byte(setting.Value), &cfg); err != nil {
		log.Printf("Failed to decode compression settings: %v", err)
		h.config.VPN.EnableCompression = defaultEnableCompression
		h.config.VPN.CompressionType = defaultCompressionType
		return
	}
	h.config.VPN.EnableCompression = cfg.EnableCompression
	h.config.VPN.CompressionType = cfg.CompressionType
}

func (h *VPNHandler) applyCompressionToRuntime() {
	if h.vpnServer == nil {
		return
	}
	compType := compression.CompressionType(h.config.VPN.CompressionType)
	if h.config.VPN.EnableCompression && compType != compression.CompressionNone {
		h.vpnServer.CompressionMgr = compression.NewCompressionManager(compType)
	} else {
		h.vpnServer.CompressionMgr = compression.NewCompressionManager(compression.CompressionNone)
	}
}
