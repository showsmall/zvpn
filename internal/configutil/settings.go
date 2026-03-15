package configutil

import (
	"encoding/json"
	"log"

	"github.com/fisker/zvpn/internal/database"
	"github.com/fisker/zvpn/models"
	"gorm.io/gorm"
)

const (
	vpnProfileSettingKey = "vpn_profile"
	vpnBannerSettingKey  = "vpn_banner"
)

type VPNProfileSettings struct {
	VPNProfileName string `json:"vpn_profile_name"`
}

type VPNBannerSettings struct {
	BannerText string `json:"banner_text"`
}

// GetVPNProfileName 获取 VPN 配置名称
func GetVPNProfileName() string {
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", vpnProfileSettingKey).First(&setting).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return "ZVPN"
		}
		log.Printf("Failed to load VPN profile name from DB: %v", err)
		return "ZVPN"
	}
	var vpnProfileSettings VPNProfileSettings
	if err := json.Unmarshal([]byte(setting.Value), &vpnProfileSettings); err != nil {
		log.Printf("Failed to unmarshal VPN profile settings: %v", err)
		return "ZVPN"
	}
	if vpnProfileSettings.VPNProfileName == "" {
		return "ZVPN"
	}
	return vpnProfileSettings.VPNProfileName
}

// GetBannerText 获取 VPN Banner 文本
func GetBannerText() string {
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", vpnBannerSettingKey).First(&setting).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return ""
		}
		log.Printf("Failed to load VPN banner from DB: %v", err)
		return ""
	}
	var bannerSettings VPNBannerSettings
	if err := json.Unmarshal([]byte(setting.Value), &bannerSettings); err != nil {
		log.Printf("Failed to unmarshal VPN banner settings: %v", err)
		return ""
	}
	return bannerSettings.BannerText
}
