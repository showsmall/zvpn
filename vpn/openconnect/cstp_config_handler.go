package openconnect

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/fisker/zvpn/internal/configutil"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

func (h *Handler) sendCSTPConfig(conn net.Conn, user *models.User, dnsServers []string, clientCipherSuite string, clientMasterSecret string, clientType ClientType, c *gin.Context) error {
	_, ipNet, err := net.ParseCIDR(h.config.VPN.Network)
	if err != nil {
		return err
	}
	netmask := net.IP(ipNet.Mask).String()
	requestedTunnelMode := getUserTunnelMode(user)
	effectiveTunnelMode := requestedTunnelMode

	hostname := configutil.GetVPNProfileName()
	if hostname == "" {
		hostname = "zvpn"
	}

	isMobile := h.detectMobileClient(c)
	mobileConfig := CalculateMobileConfig(h.config, isMobile)

	dtlsConfig := h.calculateDTLSConfig(clientCipherSuite, clientMasterSecret, mobileConfig)

	routeCalculator := NewRouteCalculator(h.config, user, effectiveTunnelMode, dnsServers)
	splitIncludeRoutes, splitExcludeRoutes := routeCalculator.CalculateRoutes()

	splitDNSDomains := h.calculateSplitDNS(user)

	if effectiveTunnelMode != "full" && len(splitIncludeRoutes) == 0 {
		log.Printf("OpenConnect: No split-include routes available for user %s in split mode; keeping requested mode=%s for client=%s and sending no split routes",
			user.Username, requestedTunnelMode, getClientName(clientType))
	}

	if effectiveTunnelMode == "full" && len(splitDNSDomains) > 0 {
		log.Printf("OpenConnect: Suppressing Split-DNS for user %s because effective tunnel mode is full", user.Username)
		splitDNSDomains = nil
	}

	cstpAcceptEncoding := getHeaderCaseInsensitive(c, "X-Cstp-Accept-Encoding", "X-CSTP-Accept-Encoding")
	dtlsAcceptEncoding := getHeaderCaseInsensitive(c, "X-Dtls-Accept-Encoding", "X-DTLS-Accept-Encoding")

	builder := NewCSTPConfigBuilder(h.config, user, effectiveTunnelMode, netmask, isMobile)
	builder.BuildBasicHeaders(hostname)
	builder.AddCompressionHeaders(cstpAcceptEncoding, dtlsAcceptEncoding)
	builder.AddMTUHeader(h.config.VPN.MTU)
	builder.AddKeepaliveHeaders(mobileConfig.DPD, mobileConfig.Keepalive)
	builder.AddDTLSHeaders(dtlsConfig.SessionID, dtlsConfig.Port, dtlsConfig.DPDStr, dtlsConfig.KeepaliveStr, dtlsConfig.CipherSuiteHeader)
	hasVPNDNS := builder.AddDNSHeaders(dnsServers)
	if effectiveTunnelMode != "full" && hasVPNDNS {
		builder.AddSplitDNSHeaders(splitDNSDomains)
	} else if len(splitDNSDomains) > 0 && !hasVPNDNS {
		log.Printf("OpenConnect: Suppressing Split-DNS for user %s because no VPN DNS servers are configured", user.Username)
	}
	builder.AddRouteHeaders(splitIncludeRoutes, splitExcludeRoutes)
	builder.AddFixedHeaders(hasVPNDNS && effectiveTunnelMode == "full")

	response := builder.String()

	log.Printf("OpenConnect: CSTP effective mode for user %s: requested=%s effective=%s include_routes=%d exclude_routes=%d split_dns=%d has_vpn_dns=%t",
		user.Username, requestedTunnelMode, effectiveTunnelMode, len(splitIncludeRoutes), len(splitExcludeRoutes), len(splitDNSDomains), hasVPNDNS)

	log.Printf("OpenConnect: ========== CSTP Config XML for user %s (VPN IP: %s) ==========", user.Username, user.VPNIP)
	log.Printf("OpenConnect: %s", response)
	log.Printf("OpenConnect: ========== End of CSTP Config XML ==========")

	if _, err = conn.Write([]byte(response)); err != nil {
		log.Printf("OpenConnect: ERROR - Failed to write CSTP config to connection: %v", err)
		return fmt.Errorf("failed to write CSTP config: %w", err)
	}

	log.Printf("OpenConnect: CSTP config sent successfully for user %s (IP: %s, MTU: %d)", user.Username, user.VPNIP, h.config.VPN.MTU)
	return nil
}

func (h *Handler) detectMobileClient(c *gin.Context) bool {
	mobileLicense := getHeaderCaseInsensitive(c, "X-Cstp-License", "X-CSTP-License")
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))
	return mobileLicense == "mobile" ||
		strings.Contains(userAgent, "android") ||
		strings.Contains(userAgent, "iphone") ||
		strings.Contains(userAgent, "ipad") ||
		strings.Contains(userAgent, "ios")
}

func (h *Handler) calculateDTLSConfig(clientCipherSuite, clientMasterSecret string, mobileConfig MobileConfig) DTLSSessionConfig {
	config := DTLSSessionConfig{}
	if !h.config.VPN.EnableDTLS {
		return config
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		log.Printf("OpenConnect: Warning - Failed to generate DTLS session ID: %v", err)
		sessionIDBytes = make([]byte, 32)
	}
	config.SessionID = hex.EncodeToString(sessionIDBytes)

	config.Port = h.config.VPN.OpenConnectPort
	if h.config.VPN.DTLSPort != "" && h.config.VPN.DTLSPort != h.config.VPN.OpenConnectPort {
		config.Port = h.config.VPN.DTLSPort
	}

	config.DPDStr = strconv.Itoa(mobileConfig.DPD)
	config.KeepaliveStr = strconv.Itoa(mobileConfig.Keepalive)

	config.CipherSuiteHeader = checkDtls12Ciphersuite(clientCipherSuite)

	if clientMasterSecret != "" && h.dtlsSessionStore != nil {
		if err := h.dtlsSessionStore.StoreMasterSecret(config.SessionID, clientMasterSecret); err != nil {
			log.Printf("OpenConnect: Failed to store master secret: %v", err)
		}
	}

	return config
}

func (h *Handler) calculateSplitDNS(user *models.User) []string {
	splitDNSDomains := []string{}

	userPolicy := user.GetPolicy()
	if userPolicy != nil {
		log.Printf("OpenConnect: Checking Split-DNS for user %s, policy SplitDNS field: '%s'", user.Username, userPolicy.SplitDNS)
		splitDNSDomains = getSplitDNSDomains(userPolicy)
		log.Printf("OpenConnect: Parsed %d Split-DNS domains for user %s: %v", len(splitDNSDomains), user.Username, splitDNSDomains)
	} else {
		log.Printf("OpenConnect: No policy found for user %s, will not send Split-DNS", user.Username)
	}

	if len(splitDNSDomains) == 0 {
		log.Printf("OpenConnect: No Split-DNS domains configured for user %s", user.Username)
	}

	return splitDNSDomains
}

