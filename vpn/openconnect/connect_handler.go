package openconnect

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/fisker/zvpn/internal/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn/policy"
	vpnserver "github.com/fisker/zvpn/vpn/server"
	"github.com/gin-gonic/gin"
)

func (h *Handler) handleConnect(c *gin.Context) {

	if !c.GetBool("authenticated") {
		log.Printf("OpenConnect: Unauthenticated CONNECT request from %s (Path: %s)", c.ClientIP(), c.Request.URL.Path)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		log.Printf("OpenConnect: Cannot get userID from context")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	var user models.User
	if err := database.DB.Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: Failed to get user info: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if h.vpnServer == nil {
		log.Printf("OpenConnect: VPN server not initialized for user %s", user.Username)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	needAlloc := user.VPNIP == ""
	if !needAlloc {
		if uid, ok := h.vpnServer.GetVPNIPUser(user.VPNIP); ok && uid != user.ID {
			needAlloc = true
		}
	}
	if needAlloc {
		vpnIP, err := h.vpnServer.AllocateVPNIP()
		if err != nil {
			log.Printf("OpenConnect: Failed to allocate VPN IP for user %s: %v", user.Username, err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		user.VPNIP = vpnIP.String()
	}
	if user.VPNIP == "" {
		log.Printf("OpenConnect: User %s has no VPN IP after allocation", user.Username)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if ip := net.ParseIP(user.VPNIP); ip != nil {
		h.vpnServer.ReserveVPNIP(ip)
	}

	clientType := detectClientType(c)
	clientName := getClientName(clientType)
	log.Printf("OpenConnect: CONNECT request from %s (user: %s, VPN IP: %s, client: %s)",
		c.ClientIP(), user.Username, user.VPNIP, clientName)

	conn, _, err := c.Writer.Hijack()
	if err != nil {
		log.Printf("OpenConnect: Failed to hijack connection: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			log.Printf("OpenConnect: Warning - Failed to set TCP_NODELAY: %v", err)
		}
	}

	if c.Request.Body != nil {
		c.Request.Body.Close()
	}

	if policy := user.GetPolicy(); policy != nil {
		user.PolicyID = policy.ID
		user.Policy = *policy
	} else {
		user.PolicyID = 0
		user.Policy = models.Policy{}
	}

	userDNSServers := getDNSServers(user.GetPolicy())

	dnsMap := make(map[string]bool)
	var dnsServers []string

	for _, dns := range userDNSServers {
		if dns != "" {
			dns = strings.TrimSpace(dns)
			if dns != "" && !dnsMap[dns] {
				dnsMap[dns] = true
				dnsServers = append(dnsServers, dns)
			}
		}
	}

	tunnelMode := getUserTunnelMode(&user)
	if len(dnsServers) == 0 {
		log.Printf("OpenConnect: No DNS configured for user %s (tunnel mode: %s), DNS will use local/system default", user.Username, tunnelMode)
	}

	clientCipherSuite := getHeaderCaseInsensitive(c, "X-Dtls12-Ciphersuite", "X-DTLS12-CipherSuite", "X-Dtls-Ciphersuite", "X-DTLS-CipherSuite")
	if clientCipherSuite == "PSK-NEGOTIATE" {
		clientCipherSuite = ""
	}

	clientMasterSecret := getHeaderCaseInsensitive(c, "X-Dtls-Master-Secret", "X-DTLS-Master-Secret")

	if err := h.sendCSTPConfig(conn, &user, dnsServers, clientCipherSuite, clientMasterSecret, clientType, c); err != nil {
		log.Printf("OpenConnect: Failed to send CSTP config: %v", err)
		conn.Close()
		return
	}

	user.Connected = true
	now := time.Now()
	user.LastSeen = &now
	if err := database.DB.Model(&user).Select("connected", "last_seen").Updates(map[string]interface{}{
		"connected": user.Connected,
		"last_seen": user.LastSeen,
	}).Error; err != nil {
		log.Printf("OpenConnect: Failed to update user connection status: %v", err)
	}

	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		clientIP := c.ClientIP()
		auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionConnect, "success",
			fmt.Sprintf("VPN connection established. VPN IP: %s", user.VPNIP), clientIP, 0)
	}

	vpnIP := net.ParseIP(user.VPNIP)
	if vpnIP == nil {
		log.Printf("OpenConnect: Invalid VPN IP: %s", user.VPNIP)
		conn.Close()
		return
	}

	tunDevice := h.vpnServer.GetTUNDevice()
	if tunDevice == nil {
		log.Printf("OpenConnect: TUN device not available")
		conn.Close()
		return
	}

	if err := h.vpnServer.CreatePolicyHooks(&user); err != nil {
		log.Printf("OpenConnect: Warning - Failed to create policy hooks: %v", err)
	}

	userAgent := c.Request.UserAgent()
	clientOS, clientVer := parseClientInfo(userAgent)
	tunnelClient := NewTunnelClient(&user, conn, vpnIP, h.vpnServer, tunDevice)

	mobileLicense := getHeaderCaseInsensitive(c, "X-Cstp-License", "X-CSTP-License")
	userAgentLower := strings.ToLower(userAgent)
	isMobile := mobileLicense == "mobile" ||
		strings.Contains(userAgentLower, "android") ||
		strings.Contains(userAgentLower, "iphone") ||
		strings.Contains(userAgentLower, "ipad") ||
		strings.Contains(userAgentLower, "ios")

	if h.config.VPN.EnableDTLS {
		h.dtlsManager.Add(user.VPNIP, &DTLSClientInfo{
			Client:   tunnelClient,
			UDPAddr:  nil,
			DTLSConn: nil,
			LastSeen: time.Now(),
			IsMobile: isMobile,
		})
	}

	bufferSize := 100
	if cfg := h.vpnServer.GetConfig(); cfg != nil {
		if cfg.VPN.WriteChanBufferSize > 0 {
			bufferSize = cfg.VPN.WriteChanBufferSize
		}
	}

	vpnClient := &vpnserver.VPNClient{
		UserID:     user.ID,
		User:       &user,
		Conn:       conn,
		IP:         vpnIP,
		UserAgent:  userAgent,
		ClientOS:   clientOS,
		ClientVer:  clientVer,
		Connected:  true,
		WriteChan:  make(chan []byte, bufferSize),
		WriteClose: make(chan struct{}),
	}
	h.vpnServer.RegisterClient(user.ID, vpnClient)

	go vpnClient.WriteLoop()

	go func() {

		time.Sleep(10 * time.Millisecond)

		dpdRespPayload := []byte{}

		for i := 0; i < 2; i++ {
			if err := tunnelClient.sendPacket(PacketTypeDPDResp, dpdRespPayload); err != nil {
				log.Printf("OpenConnect: 通过TCP通道发送DPD响应 #%d失败: %v", i+1, err)
				break
			}

			if i < 1 {
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("OpenConnect: PANIC in HandleTunnelData for user %s: %v\n%s", user.Username, r, debug.Stack())
			if client, exists := h.vpnServer.GetClient(user.ID); exists && client != nil {
				select {
				case <-client.WriteClose:
				default:
					close(client.WriteClose)
				}
			}
			if conn != nil {
				conn.Close()
			}
		}
	}()

	if err := tunnelClient.HandleTunnelData(); err != nil {
		log.Printf("OpenConnect: HandleTunnelData error for user %s: %v", user.Username, err)
	}

	tunnelMode = getUserTunnelMode(&user)
	log.Printf("OpenConnect: Tunnel closed for user %s (VPN IP: %s, Tunnel Mode: %s)",
		user.Username, user.VPNIP, tunnelMode)

	client, exists := h.vpnServer.GetClient(user.ID)
	disconnectSent := false
	if exists && client != nil {

		disconnectPacket := tunnelClient.BuildCSTPPacket(PacketTypeDisconnect, nil)

		select {
		case client.WriteChan <- disconnectPacket:
			disconnectSent = true
			if tunnelMode == "full" {
				time.Sleep(2700 * time.Millisecond)
			} else {
				time.Sleep(300 * time.Millisecond)
			}
		default:

			if conn != nil {
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
					if err := tunnelClient.sendPacket(PacketTypeDisconnect, nil); err != nil {
						log.Printf("OpenConnect: Failed to send DISCONNECT packet directly: %v", err)
					} else {
						disconnectSent = true
						if tunnelMode == "full" {

							time.Sleep(2500 * time.Millisecond)
						} else {
							time.Sleep(200 * time.Millisecond)
						}
					}
					tcpConn.SetWriteDeadline(time.Time{})
				} else {
					if err := tunnelClient.sendPacket(PacketTypeDisconnect, nil); err != nil {
						log.Printf("OpenConnect: Failed to send DISCONNECT packet: %v", err)
					} else {
						disconnectSent = true
						if tunnelMode == "full" {

							time.Sleep(2500 * time.Millisecond)
						} else {
							time.Sleep(200 * time.Millisecond)
						}
					}
				}
			}
		}
	} else {
		log.Printf("OpenConnect: Cannot send DISCONNECT packet - client not available")
	}

	if disconnectSent && tunnelMode == "full" {
		time.Sleep(1000 * time.Millisecond)
	}

	if tunnelMode == "full" && !disconnectSent {
		log.Printf("OpenConnect: WARNING - Failed to send DISCONNECT packet to client %s (full tunnel mode)", user.Username)
	}

	if exists && client != nil {

		select {
		case <-client.WriteClose:

		default:

			if disconnectSent {
				if tunnelMode == "full" {
					time.Sleep(500 * time.Millisecond)
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			}
			close(client.WriteClose)

			time.Sleep(50 * time.Millisecond)
		}

		if conn != nil {
			closeConnectionGracefully(conn)
		}
	} else if conn != nil {

		closeConnectionGracefully(conn)
	}

	if err := h.vpnServer.RemovePolicyHooks(user.ID); err != nil {
		log.Printf("OpenConnect: Warning - Failed to remove policy hooks: %v", err)
	}

	h.vpnServer.UnregisterClient(user.ID, user.VPNIP)

	if h.config.VPN.EnableDTLS {
		clientInfo, exists := h.dtlsManager.GetByVPNIP(user.VPNIP)
		if exists && clientInfo != nil {

			if clientInfo.DTLSConn != nil {
				log.Printf("OpenConnect: Closing DTLS connection for user %s (VPN IP: %s)", user.Username, user.VPNIP)

				if err := clientInfo.DTLSConn.Close(); err != nil {

					errStr := err.Error()
					if !strings.Contains(errStr, "use of closed network connection") &&
						!strings.Contains(errStr, "connection reset by peer") &&
						!strings.Contains(errStr, "broken pipe") {
						log.Printf("OpenConnect: Warning - Failed to close DTLS connection: %v", err)
					}
				}

				clientInfo.DTLSConn = nil
			}

			if client, exists := h.vpnServer.GetClient(user.ID); exists && client != nil {
				client.DTLSConn = nil
			}
		}
		h.dtlsManager.Remove(user.VPNIP)
		log.Printf("OpenConnect: Unregistered DTLS client for user %s (VPN IP: %s)", user.Username, user.VPNIP)
	}

	if h.vpnServer != nil && user.VPNIP != "" {
		if ip := net.ParseIP(user.VPNIP); ip != nil {
			h.vpnServer.ReleaseVPNIP(ip)
		}
	}
	user.Connected = false
	user.VPNIP = ""
	if err := database.DB.Model(&user).Select("connected", "vpn_ip").Updates(map[string]interface{}{
		"connected": false,
		"vpn_ip":    "",
	}).Error; err != nil {
		log.Printf("OpenConnect: Failed to update user status on disconnect: %v", err)
	}

	auditLogger2 := policy.GetAuditLogger()
	if auditLogger2 != nil {
		auditLogger2.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionDisconnect, "success",
			fmt.Sprintf("VPN connection closed. VPN IP: %s", user.VPNIP), user.VPNIP, 0)
	}
}

func (h *Handler) TunnelHandler(c *gin.Context) {

	log.Printf("OpenConnect: Non-CONNECT tunnel request: %s %s", c.Request.Method, c.Request.URL.Path)
	c.AbortWithStatus(http.StatusMethodNotAllowed)
}

func (h *Handler) Index(c *gin.Context) {
	c.String(http.StatusOK, "Welcome to ZVPN OpenConnect Server")
}

func closeConnectionGracefully(conn net.Conn) {

	if tlsConn, ok := conn.(*tls.Conn); ok {

		tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		buf := make([]byte, 1)
		tlsConn.Read(buf)

		tlsConn.SetReadDeadline(time.Time{})

		if err := tlsConn.Close(); err != nil {

			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "connection reset by peer") &&
				!strings.Contains(errStr, "broken pipe") {
				log.Printf("OpenConnect: Warning - Failed to close TLS connection: %v", err)
			}
		}
	} else {

		if err := conn.Close(); err != nil {

			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "connection reset by peer") &&
				!strings.Contains(errStr, "broken pipe") {
				log.Printf("OpenConnect: Warning - Failed to close connection: %v", err)
			}
		}
	}
}

