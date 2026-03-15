package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/fisker/zvpn/internal/database"
	"github.com/fisker/zvpn/models"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"gorm.io/gorm"
)

// CertInfo holds certificate metadata for API responses
type CertInfo struct {
	SNI           string
	CommonName    string
	DNSNames      []string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	IsExpired     bool
	IsDefault     bool
}

// Manager manages TLS certificates with SNI support
type Manager struct {
	certs       map[string]*tls.Certificate
	defaultCert *tls.Certificate
	tempCert    *tls.Certificate
	mu          sync.RWMutex
}

// New creates a new certificate manager
func New() *Manager {
	tempCert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		log.Printf("WARNING: Failed to generate temporary certificate: %v", err)
		return &Manager{
			certs:    make(map[string]*tls.Certificate),
			tempCert: nil,
		}
	}
	return &Manager{
		certs:    make(map[string]*tls.Certificate),
		tempCert: &tempCert,
	}
}

func filterRootCertificate(cert *tls.Certificate) {
	if len(cert.Certificate) <= 1 {
		return
	}
	originalLength := len(cert.Certificate)
	for len(cert.Certificate) > 1 {
		lastIdx := len(cert.Certificate) - 1
		lastCert, err := x509.ParseCertificate(cert.Certificate[lastIdx])
		if err != nil {
			break
		}
		if lastCert.Issuer.String() == lastCert.Subject.String() {
			log.Printf("Certificate Manager: Filtering out root certificate - CN: %s", lastCert.Subject.CommonName)
			cert.Certificate = cert.Certificate[:lastIdx]
		} else {
			break
		}
	}
	if len(cert.Certificate) < originalLength {
		log.Printf("Certificate Manager: Chain filtered %d -> %d certs", originalLength, len(cert.Certificate))
	}
	if len(cert.Certificate) > 1 {
		serverCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			intermediateCert, err := x509.ParseCertificate(cert.Certificate[1])
			if err == nil && serverCert.Issuer.String() != intermediateCert.Subject.String() {
				log.Printf("Certificate Manager: WARNING - Chain order may be incorrect")
			}
		}
	}
}

func logCertInfo(label string, cert *tls.Certificate, certFile, keyFile string) {
	if cert.Leaf == nil {
		return
	}
	daysUntilExpiry := int(cert.Leaf.NotAfter.Sub(time.Now()).Hours() / 24)
	log.Printf("Certificate Manager: Loaded %s from %s, %s - CN: %s, valid %d days",
		label, certFile, keyFile, cert.Leaf.Subject.CommonName, daysUntilExpiry)
	if daysUntilExpiry < 0 {
		log.Printf("Certificate Manager: FATAL - Certificate EXPIRED")
	} else if daysUntilExpiry <= 7 {
		log.Printf("Certificate Manager: WARNING - Expires in %d days", daysUntilExpiry)
	}
}

// LoadDefaultCert loads the default certificate from files
func (m *Manager) LoadDefaultCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load default certificate: %w", err)
	}
	filterRootCertificate(&cert)
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		cert.Leaf = leaf
	}
	m.mu.Lock()
	m.defaultCert = &cert
	m.mu.Unlock()
	if len(cert.Certificate) < 1 {
		return fmt.Errorf("certificate chain is empty")
	}
	m.loadCertificate(&cert)
	logCertInfo("default", &cert, certFile, keyFile)
	return nil
}

// AddCert adds an SNI certificate from files
func (m *Manager) AddCert(sni string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load certificate for SNI %s: %w", sni, err)
	}
	filterRootCertificate(&cert)
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		cert.Leaf = leaf
	}
	m.mu.Lock()
	m.certs[strings.ToLower(sni)] = &cert
	m.mu.Unlock()
	log.Printf("Certificate Manager: Added SNI '%s' from %s, %s", sni, certFile, keyFile)
	m.loadCertificate(&cert)
	return nil
}

// AddCertFromBytes adds an SNI certificate from raw bytes
func (m *Manager) AddCertFromBytes(sni string, certBytes, keyBytes []byte) error {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("load certificate from bytes for SNI %s: %w", sni, err)
	}
	filterRootCertificate(&cert)
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		cert.Leaf = leaf
	}
	if err := m.saveCertToDB(sni, certBytes, keyBytes, &cert); err != nil {
		log.Printf("WARNING: Failed to save certificate to database: %v", err)
	}
	m.mu.Lock()
	m.certs[strings.ToLower(sni)] = &cert
	m.mu.Unlock()
	log.Printf("Certificate Manager: Added SNI '%s' from bytes", sni)
	m.loadCertificate(&cert)
	return nil
}

// RemoveCert removes an SNI certificate
func (m *Manager) RemoveCert(sni string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sniLower := strings.ToLower(sni)
	if _, exists := m.certs[sniLower]; !exists {
		return fmt.Errorf("certificate for SNI '%s' not found", sni)
	}
	if err := database.DB.Where("sni = ?", sniLower).Delete(&models.Certificate{}).Error; err != nil {
		log.Printf("WARNING: Failed to delete certificate from database: %v", err)
	}
	delete(m.certs, sniLower)
	log.Printf("Certificate Manager: Removed SNI '%s'", sni)
	return nil
}

func (m *Manager) saveCertToDB(sni string, certBytes, keyBytes []byte, cert *tls.Certificate) error {
	sniLower := strings.ToLower(sni)
	certRecord := &models.Certificate{
		SNI:      sniLower,
		CertData: certBytes,
		KeyData:  keyBytes,
		IsActive: true,
	}
	if cert.Leaf != nil {
		dnsNamesBytes, _ := json.Marshal(cert.Leaf.DNSNames)
		certRecord.CommonName = cert.Leaf.Subject.CommonName
		certRecord.DNSNames = string(dnsNamesBytes)
		certRecord.Issuer = cert.Leaf.Issuer.CommonName
		certRecord.NotBefore = cert.Leaf.NotBefore
		certRecord.NotAfter = cert.Leaf.NotAfter
	}
	return database.DB.Where("sni = ?", sniLower).Assign(certRecord).FirstOrCreate(certRecord).Error
}

// LoadCertsFromDB loads SNI certificates from database
func (m *Manager) LoadCertsFromDB() error {
	var certs []models.Certificate
	if err := database.DB.Where("is_active = ?", true).Find(&certs).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil
		}
		return fmt.Errorf("load certificates from database: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, certRecord := range certs {
		cert, err := tls.X509KeyPair(certRecord.CertData, certRecord.KeyData)
		if err != nil {
			log.Printf("WARNING: Failed to load SNI '%s' from DB: %v", certRecord.SNI, err)
			continue
		}
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			leaf, _ := x509.ParseCertificate(cert.Certificate[0])
			cert.Leaf = leaf
		}
		sniLower := strings.ToLower(certRecord.SNI)
		m.certs[sniLower] = &cert
		m.buildNameToCertificateUnlocked(&cert)
		log.Printf("Certificate Manager: Loaded SNI '%s' from database", certRecord.SNI)
	}
	log.Printf("Certificate Manager: Loaded %d SNI certificates from database", len(certs))
	return nil
}

// GetCerts returns all SNI certificates as CertInfo map
func (m *Manager) GetCerts() map[string]CertInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]CertInfo)
	for sni, cert := range m.certs {
		if cert.Leaf != nil {
			info := m.certToInfo(sni, cert, false)
			result[sni] = info
		}
	}
	return result
}

// GetDefaultCertInfo returns the default certificate info
func (m *Manager) GetDefaultCertInfo() *CertInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.defaultCert == nil || m.defaultCert.Leaf == nil {
		return nil
	}
	info := m.certToInfo("", m.defaultCert, true)
	return &info
}

// LoadDefaultCertFromBytes loads default certificate from raw bytes
func (m *Manager) LoadDefaultCertFromBytes(certBytes, keyBytes []byte) error {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("load default certificate from bytes: %w", err)
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		cert.Leaf = leaf
	}
	m.mu.Lock()
	m.defaultCert = &cert
	m.mu.Unlock()
	log.Printf("Certificate Manager: Loaded default certificate from bytes")
	m.loadCertificate(&cert)
	return nil
}

func (m *Manager) certToInfo(sni string, cert *tls.Certificate, isDefault bool) CertInfo {
	info := CertInfo{SNI: sni, IsDefault: isDefault}
	if cert.Leaf != nil {
		info.CommonName = cert.Leaf.Subject.CommonName
		info.DNSNames = cert.Leaf.DNSNames
		info.Issuer = cert.Leaf.Issuer.CommonName
		info.NotBefore = cert.Leaf.NotBefore
		info.NotAfter = cert.Leaf.NotAfter
		daysRemaining := int(cert.Leaf.NotAfter.Sub(time.Now()).Hours() / 24)
		info.DaysRemaining = daysRemaining
		info.IsExpired = daysRemaining < 0
	}
	return info
}

func (m *Manager) loadCertificate(cert *tls.Certificate) {
	m.buildNameToCertificate(cert)
}

func (m *Manager) buildNameToCertificate(cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buildNameToCertificateUnlocked(cert)
}

func (m *Manager) buildNameToCertificateUnlocked(cert *tls.Certificate) {
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		cert.Leaf = leaf
	}
	if cert.Leaf == nil {
		return
	}
	m.certs["default"] = cert
	if cert.Leaf.Subject.CommonName != "" && len(cert.Leaf.DNSNames) == 0 {
		m.certs[strings.ToLower(cert.Leaf.Subject.CommonName)] = cert
	}
	for _, san := range cert.Leaf.DNSNames {
		m.certs[strings.ToLower(san)] = cert
	}
}

// GetCertificateBySNI returns the certificate for the given server name (SNI)
func (m *Manager) GetCertificateBySNI(serverName string) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	name := strings.ToLower(serverName)
	if cert, ok := m.certs[name]; ok {
		if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate invalid")
		}
		return cert, nil
	}
	if len(name) > 1 {
		labels := strings.Split(name, ".")
		if len(labels) > 1 {
			labels[0] = "*"
			wildcardName := strings.Join(labels, ".")
			if cert, ok := m.certs[wildcardName]; ok {
				if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
					return nil, fmt.Errorf("certificate invalid")
				}
				return cert, nil
			}
		}
	}
	if cert, ok := m.certs["default"]; ok {
		if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate invalid")
		}
		return cert, nil
	}
	if m.defaultCert != nil {
		if len(m.defaultCert.Certificate) == 0 || m.defaultCert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate invalid")
		}
		return m.defaultCert, nil
	}
	return m.getTempCertificate()
}

func (m *Manager) getTempCertificate() (*tls.Certificate, error) {
	m.mu.RLock()
	tempCert := m.tempCert
	m.mu.RUnlock()
	if tempCert != nil {
		return tempCert, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tempCert != nil {
		return m.tempCert, nil
	}
	cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		log.Printf("TLS: Failed to generate temporary certificate: %v", err)
		return nil, fmt.Errorf("generate temporary certificate: %w", err)
	}
	m.tempCert = &cert
	log.Printf("TLS: Generated temporary certificate (localhost) as fallback")
	return m.tempCert, nil
}

// HasValidDefaultCert returns true if a valid default certificate is loaded
func (m *Manager) HasValidDefaultCert() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultCert != nil && len(m.defaultCert.Certificate) > 0 && m.defaultCert.PrivateKey != nil
}
