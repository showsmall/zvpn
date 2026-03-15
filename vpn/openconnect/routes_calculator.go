package openconnect

import (
	"log"
	"net"
	"strings"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/models"
)

// RouteCalculator 路由计算器
type RouteCalculator struct {
	config     *config.Config
	user       *models.User
	tunnelMode string
	dnsServers []string
}

// NewRouteCalculator 创建一个新的路由计算器
func NewRouteCalculator(cfg *config.Config, user *models.User, tunnelMode string, dnsServers []string) *RouteCalculator {
	return &RouteCalculator{
		config:     cfg,
		user:       user,
		tunnelMode: tunnelMode,
		dnsServers: dnsServers,
	}
}

// CalculateRoutes 计算隧道路由
func (rc *RouteCalculator) CalculateRoutes() (splitIncludeRoutes, splitExcludeRoutes []string) {
	routeMap := make(map[string]bool)        // 用于去重 split-include 路由
	excludeRouteMap := make(map[string]bool) // 用于去重 split-exclude 路由

	// 1. 从 DNS 服务器计算路由（仅在非 full 模式下）
	splitIncludeRoutes = rc.calculateDNSRoutes(routeMap)

	// 2. 从用户策略计算路由
	splitIncludeRoutes = rc.calculatePolicyRoutes(routeMap, splitIncludeRoutes)

	// 3. 在 full 模式下计算排除路由
	if rc.tunnelMode == "full" {
		splitExcludeRoutes = rc.calculateExcludeRoutes(excludeRouteMap)
	}

	// 4. 处理 AllowLan 配置
	splitExcludeRoutes = rc.handleAllowLan(excludeRouteMap, splitExcludeRoutes)

	return splitIncludeRoutes, splitExcludeRoutes
}

// calculateDNSRoutes 从 DNS 服务器计算路由
func (rc *RouteCalculator) calculateDNSRoutes(routeMap map[string]bool) []string {
	if rc.tunnelMode == "full" || len(rc.dnsServers) == 0 {
		return nil
	}

	var routes []string
	for _, dns := range rc.dnsServers {
		if dns == "" {
			continue
		}
		dns = strings.TrimSpace(dns)
		dnsIP := net.ParseIP(dns)
		if dnsIP == nil {
			continue
		}

		if isPrivateIP(dnsIP) {
			dnsNetwork := getDNSServerNetwork(dnsIP)
			if dnsNetwork != "" && dnsNetwork != rc.config.VPN.Network {
				if !routeMap[dnsNetwork] {
					routeMap[dnsNetwork] = true
					routes = append(routes, dnsNetwork)
				}
			}
		}
	}
	return routes
}

// calculatePolicyRoutes 从用户策略计算路由
func (rc *RouteCalculator) calculatePolicyRoutes(routeMap map[string]bool, existingRoutes []string) []string {
	userPolicy := rc.user.GetPolicy()
	if userPolicy == nil || len(userPolicy.Routes) == 0 {
		return existingRoutes
	}

	routes := existingRoutes
	for _, route := range userPolicy.Routes {
		if route.Network == "" {
			continue
		}

		normalizedRoute, _, err := parseRouteNetwork(route.Network)
		if err != nil {
			log.Printf("OpenConnect: WARNING - Invalid route format '%s' for user %s: %v (skipping)", route.Network, rc.user.Username, err)
			continue
		}

		if normalizedRoute == rc.config.VPN.Network {
			continue
		}

		if normalizedRoute == "0.0.0.0/0" {
			log.Printf("OpenConnect: WARNING - Default route (0.0.0.0/0) is not allowed in split mode for user %s (skipping)", rc.user.Username)
			continue
		}

		if !routeMap[normalizedRoute] {
			routeMap[normalizedRoute] = true
			routes = append(routes, normalizedRoute)
		}
	}
	return routes
}

// calculateExcludeRoutes 计算排除路由
func (rc *RouteCalculator) calculateExcludeRoutes(excludeRouteMap map[string]bool) []string {
	userPolicy := rc.user.GetPolicy()
	if userPolicy == nil || len(userPolicy.ExcludeRoutes) == 0 {
		return nil
	}

	var routes []string
	for _, excludeRoute := range userPolicy.ExcludeRoutes {
		if excludeRoute.Network == "" {
			continue
		}

		normalizedRoute, _, err := parseRouteNetwork(excludeRoute.Network)
		if err != nil {
			log.Printf("OpenConnect: Invalid exclude route '%s' for user %s: %v (skipping)", excludeRoute.Network, rc.user.Username, err)
			continue
		}

		if excludeRoute.Network == "0.0.0.0/255.255.255.255" {
			if !excludeRouteMap[excludeRoute.Network] {
				excludeRouteMap[excludeRoute.Network] = true
				routes = append(routes, excludeRoute.Network)
				log.Printf("OpenConnect: Added exclude route '%s' (allow_lan format) for user %s in full tunnel mode", excludeRoute.Network, rc.user.Username)
			}
		} else {
			if !excludeRouteMap[normalizedRoute] {
				excludeRouteMap[normalizedRoute] = true
				routes = append(routes, normalizedRoute)
				log.Printf("OpenConnect: Added exclude route '%s' (normalized from '%s') for user %s in full tunnel mode", normalizedRoute, excludeRoute.Network, rc.user.Username)
			}
		}
	}
	return routes
}

// handleAllowLan 处理 AllowLan 配置
func (rc *RouteCalculator) handleAllowLan(excludeRouteMap map[string]bool, existingRoutes []string) []string {
	if rc.tunnelMode != "full" {
		return existingRoutes
	}

	allowLan := false
	for _, group := range rc.user.Groups {
		if group.AllowLan {
			allowLan = true
			break
		}
	}

	if !allowLan {
		return existingRoutes
	}

	routes := existingRoutes
	allowLanRoute := "0.0.0.0/255.255.255.255"
	if !excludeRouteMap[allowLanRoute] {
		excludeRouteMap[allowLanRoute] = true
		routes = append([]string{allowLanRoute}, routes...)
		log.Printf("OpenConnect: Auto-added allow_lan route (0.0.0.0/255.255.255.255) for user %s (group allow_lan enabled)", rc.user.Username)
	} else {
		log.Printf("OpenConnect: allow_lan route (0.0.0.0/255.255.255.255) already configured in policy for user %s", rc.user.Username)
		// 将 allowLanRoute 移到最前面
		var filteredRoutes []string
		for _, route := range routes {
			if route != allowLanRoute {
				filteredRoutes = append(filteredRoutes, route)
			}
		}
		routes = append([]string{allowLanRoute}, filteredRoutes...)
	}
	return routes
}

