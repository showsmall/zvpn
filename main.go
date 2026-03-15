package main

import (
	"fmt"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/internal/database"
	"github.com/fisker/zvpn/server"
	vpnserver "github.com/fisker/zvpn/vpn/server"
)

var (
	Version   = "-"
	BuildTime = "-"
	GitCommit = "-"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	cfg := config.Load()

	if err := database.Init(cfg); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	vpnServer, err := vpnserver.NewVPNServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize VPN server: %w", err)
	}

	if err := server.New(cfg, vpnServer).Start(); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
