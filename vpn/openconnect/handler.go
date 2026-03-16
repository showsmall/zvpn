package openconnect

import (
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/internal/auth"
	"github.com/fisker/zvpn/internal/utils"
	"github.com/fisker/zvpn/vpn/security"
	vpnserver "github.com/fisker/zvpn/vpn/server"
	"github.com/gin-gonic/gin"
)

type DTLSClientInfo struct {
	Client        *TunnelClient
	UDPAddr       *net.UDPAddr
	DTLSConn      net.Conn
	LastSeen      time.Time
	DTLSSessionID string
	IsMobile      bool // 是否为移动端客户端
}

type Handler struct {
	config               *config.Config
	vpnServer            *vpnserver.VPNServer
	ldapAuthenticator    *auth.LDAPAuthenticator
	tunDevice            *vpnserver.TUNDevice
	dtlsListener         net.Listener
	dtlsRawUDPConn       *net.UDPConn
	dtlsManager          *DTLSClientManager // 使用优化的 DTLS 客户端管理器
	dtlsSessionStore     *dtlsSessionStore
	bruteforceProtection *security.BruteforceProtection
}

type ClientType string

const (
	ClientTypeOpenConnect ClientType = "openconnect"
	ClientTypeAnyConnect  ClientType = "anyconnect"
	ClientTypeCustom      ClientType = "custom"
	ClientTypeUnknown     ClientType = "unknown"
)

func detectClientType(c *gin.Context) ClientType {

	xAggregateAuth := c.Request.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := c.Request.Header.Get("X-Transcend-Version")

	if xAggregateAuth == "1" && xTranscendVersion == "1" {
		return ClientTypeAnyConnect
	}

	if xAggregateAuth != "" && xTranscendVersion != "" {
		return ClientTypeAnyConnect
	}

	userAgent := strings.ToLower(c.Request.UserAgent())

	if strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect") {
		return ClientTypeAnyConnect
	} else if strings.Contains(userAgent, "openconnect") {
		return ClientTypeOpenConnect
	}

	return ClientTypeUnknown
}

func getClientName(clientType ClientType) string {
	switch clientType {
	case ClientTypeOpenConnect:
		return "OpenConnect"
	case ClientTypeAnyConnect:
		return "AnyConnect"
	case ClientTypeCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

func parseClientInfo(ua string) (osName string, version string) {
	lc := strings.ToLower(ua)

	switch {
	case strings.Contains(lc, "windows"):
		osName = "Windows"
	case strings.Contains(lc, "mac os") || strings.Contains(lc, "macintosh") || strings.Contains(lc, "darwin"):
		osName = "macOS"
	case strings.Contains(lc, "android"):
		osName = "Android"
	case strings.Contains(lc, "iphone") || strings.Contains(lc, "ipad") || strings.Contains(lc, "ios"):
		osName = "iOS"
	case strings.Contains(lc, "linux"):
		osName = "Linux"
	default:
		osName = ""
	}

	reClientVer := regexp.MustCompile(`(?i)(openconnect|anyconnect)[^0-9]*([0-9][0-9\\.\\-]+)`)
	if matches := reClientVer.FindStringSubmatch(ua); len(matches) == 3 {
		version = matches[2]
	}
	return
}

func getHeaderCaseInsensitive(c *gin.Context, names ...string) string {
	for _, name := range names {
		if value := c.GetHeader(name); value != "" {
			return value
		}
	}
	return ""
}

func NewHandler(cfg *config.Config, vpnServer *vpnserver.VPNServer) *Handler {
	var ldapAuth *auth.LDAPAuthenticator
	if cfg.LDAP.Enabled {
		ldapConfig := &auth.LDAPConfig{
			Enabled:      cfg.LDAP.Enabled,
			Host:         cfg.LDAP.Host,
			Port:         cfg.LDAP.Port,
			BindDN:       cfg.LDAP.BindDN,
			BindPassword: cfg.LDAP.BindPassword,
			BaseDN:       cfg.LDAP.BaseDN,
			UserFilter:   cfg.LDAP.UserFilter,
			AdminGroup:   cfg.LDAP.AdminGroup,
		}
		ldapAuth = auth.NewLDAPAuthenticator(ldapConfig)
	}

	bruteforceProtection := utils.TryGetBruteforceProtectionFromVPNServer(vpnServer)
	if bruteforceProtection != nil {
		log.Printf("OpenConnect: Using shared bruteforce protection instance from VPNServer")
	} else if cfg.VPN.EnableBruteforceProtection {
		initializer := utils.NewBruteforceProtectionInitializer(cfg)
		if vpnServer != nil {
			initializer.SetEBPFProgram(utils.TryGetEBPFProgramFromVPNServer(vpnServer))
		}
		bruteforceProtection = initializer.Initialize("OpenConnect")
	}

	handler := &Handler{
		config:               cfg,
		vpnServer:            vpnServer,
		ldapAuthenticator:    ldapAuth,
		dtlsManager:          NewDTLSClientManager(),
		bruteforceProtection: bruteforceProtection,
	}

	if vpnServer != nil {
		if tunDevice := vpnServer.GetTUNDevice(); tunDevice != nil {
			handler.tunDevice = tunDevice
		} else {
			log.Printf("OpenConnect: Warning - No TUN device available from VPNServer")
		}
	}

	return handler
}

func (h *Handler) SetupRoutes(router *gin.Engine) {

	router.Use(h.AuthMiddleware)

	router.Handle("CONNECT", "/CSCOSSLC/tunnel", h.handleConnect)

	router.GET("/", h.Index)
	router.POST("/", h.GetConfig)
	router.POST("/auth", h.Authenticate)
	router.GET("/profile.xml", h.GetProfile)

	tunnelGroup := router.Group("/CSCOSSLC")
	tunnelGroup.Use(h.ConnectMiddleware)
	tunnelGroup.GET("/tunnel", h.TunnelHandler)
	tunnelGroup.POST("/tunnel", h.TunnelHandler)
}

