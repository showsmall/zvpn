package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/internal/certmanager"
	"github.com/fisker/zvpn/middleware"
	"github.com/fisker/zvpn/routes"
	vpnserver "github.com/fisker/zvpn/vpn/server"
	"github.com/fisker/zvpn/vpn/openconnect"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg              *config.Config
	vpnServer        *vpnserver.VPNServer
	httpServer       *http.Server
	httpsServer      *http.Server
	ocHandler        *openconnect.Handler
	certManager      *certmanager.Manager
	shutdownComplete chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
}

func New(cfg *config.Config, vpnServer *vpnserver.VPNServer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		cfg:              cfg,
		vpnServer:        vpnServer,
		certManager:      certmanager.New(),
		shutdownComplete: make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
	}

	if err := server.certManager.LoadDefaultCert(cfg.VPN.CertFile, cfg.VPN.KeyFile); err != nil {
		log.Printf("ERROR: Failed to load default certificate: %v", err)
		log.Printf("ERROR: Server will start but TLS connections may fail")
	}

	if err := server.certManager.LoadCertsFromDB(); err != nil {
		log.Printf("WARNING: Failed to load SNI certificates from database: %v", err)
	}

	return server
}

func (s *Server) Start() error {
	s.ocHandler = openconnect.NewHandler(s.cfg, s.vpnServer)
	go s.startAuditLogFlusher()
	s.startHTTPServer()
	s.startHTTPSServer()

	if s.cfg.VPN.EnableDTLS {
		if err := s.ocHandler.StartDTLSServer(); err != nil {
			log.Printf("Failed to start DTLS server: %v (clients will use SSL/TLS only)", err)
		} else {
			log.Printf("DTLS server started on UDP port %s", s.cfg.VPN.OpenConnectPort)
		}
	}

	s.waitForShutdown()
	return nil
}

func (s *Server) startAuditLogFlusher() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	flush := func() {
		if auditLogger := policy.GetAuditLogger(); auditLogger != nil {
			if err := auditLogger.Flush(); err != nil {
				log.Printf("Failed to flush audit logs: %v", err)
			}
		}
	}
	for {
		select {
		case <-ticker.C:
			flush()
		case <-s.ctx.Done():
			flush()
			return
		}
	}
}

func (s *Server) startHTTPServer() {
	router := routes.SetupRouter(s.cfg, s.vpnServer, s)
	s.httpServer = &http.Server{
		Addr:    s.cfg.Server.Host + ":" + s.cfg.Server.Port,
		Handler: router,
	}
	go func() {
		log.Printf("HTTP server (Management API) starting on %s:%s", s.cfg.Server.Host, s.cfg.Server.Port)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
}

func (s *Server) startHTTPSServer() {
	router := gin.Default()
	router.Use(middleware.CorsMiddleware())
	s.ocHandler.SetupRoutes(router)
	router.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "Not Found")
	})

	customHandler := &connectHandler{
		ginHandler: router,
		ocHandler:  s.ocHandler,
	}

	cipherSuites := tls.CipherSuites()
	selectedCipherSuites := make([]uint16, 0, len(cipherSuites))
	for _, cs := range cipherSuites {
		selectedCipherSuites = append(selectedCipherSuites, cs.ID)
	}

	tlsConfig := &tls.Config{
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS11,
		CipherSuites: selectedCipherSuites,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := s.certManager.GetCertificateBySNI(chi.ServerName)
			if err != nil {
				log.Printf("TLS: GetCertificate ERROR - SNI: %s, Error: %v", chi.ServerName, err)
			}
			return cert, err
		},
	}

	errorLogWriter := &tlsErrorLogger{
		normalErrors: map[string]bool{
			"EOF":                              true,
			"connection reset by peer":         true,
			"broken pipe":                      true,
			"use of closed network connection": true,
		},
	}

	s.httpsServer = &http.Server{
		Addr:         s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort,
		Handler:      customHandler,
		TLSConfig:    tlsConfig,
		ErrorLog:     log.New(errorLogWriter, "HTTPS Server: ", log.LstdFlags|log.Lmicroseconds),
		ReadTimeout:  100 * time.Second,
		WriteTimeout: 100 * time.Second,
	}

	go func() {
		log.Printf("HTTPS server (OpenConnect) starting on %s:%s", s.cfg.Server.Host, s.cfg.VPN.OpenConnectPort)

		if !s.certManager.HasValidDefaultCert() {
			log.Fatalf("HTTPS: Default certificate invalid! Check: %s, %s", s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		}

		addr := s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("HTTPS: Failed to listen on %s: %v", addr, err)
		}

		log.Printf("HTTPS: Listening on %s", addr)
		if err := s.httpsServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()
}

func (s *Server) waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	s.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown: %v", err)
		}
	}
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server shutdown: %v", err)
		}
	}
	if err := s.vpnServer.Stop(); err != nil {
		log.Printf("VPN server shutdown: %v", err)
	}

	log.Println("Server exited")
	close(s.shutdownComplete)
}

// Certificate management API
func (s *Server) AddSNICert(sni string, certFile, keyFile string) error {
	return s.certManager.AddCert(sni, certFile, keyFile)
}

func (s *Server) AddSNICertFromBytes(sni string, certBytes, keyBytes []byte) error {
	return s.certManager.AddCertFromBytes(sni, certBytes, keyBytes)
}

func (s *Server) RemoveSNICert(sni string) error {
	return s.certManager.RemoveCert(sni)
}

func (s *Server) GetSNICerts() map[string]handlers.CertInfo {
	certs := s.certManager.GetCerts()
	result := make(map[string]handlers.CertInfo)
	for k, v := range certs {
		result[k] = toHandlersCertInfo(v)
	}
	return result
}

func (s *Server) GetDefaultCert() *handlers.CertInfo {
	info := s.certManager.GetDefaultCertInfo()
	if info == nil {
		return nil
	}
	c := toHandlersCertInfo(*info)
	return &c
}

func toHandlersCertInfo(v certmanager.CertInfo) handlers.CertInfo {
	return handlers.CertInfo{
		SNI:           v.SNI,
		CommonName:    v.CommonName,
		DNSNames:      v.DNSNames,
		Issuer:        v.Issuer,
		NotBefore:     v.NotBefore,
		NotAfter:      v.NotAfter,
		DaysRemaining: v.DaysRemaining,
		IsExpired:     v.IsExpired,
		IsDefault:     v.IsDefault,
	}
}

func (s *Server) UpdateDefaultCert(certFile, keyFile string) error {
	return s.certManager.LoadDefaultCert(certFile, keyFile)
}

func (s *Server) UpdateDefaultCertFromBytes(certBytes, keyBytes []byte) error {
	return s.certManager.LoadDefaultCertFromBytes(certBytes, keyBytes)
}

func (s *Server) UpdateDefaultCertFromBytesAndSave(certBytes, keyBytes []byte) error {
	certFile := s.cfg.VPN.CertFile
	keyFile := s.cfg.VPN.KeyFile
	if err := os.WriteFile(certFile, certBytes, 0600); err != nil {
		return fmt.Errorf("save certificate file: %w", err)
	}
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		return fmt.Errorf("save key file: %w", err)
	}
	return s.certManager.LoadDefaultCert(certFile, keyFile)
}
