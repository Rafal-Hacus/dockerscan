package report

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

const (
	// DefaultHTTPAddr is where results are served over plain HTTP
	DefaultHTTPAddr = ":80"

	// DefaultHTTPSAddr is where results are served over HTTPS
	DefaultHTTPSAddr = ":443"
)

// Scan states reported by the server until a report is available
const (
	StatusScanning = "scanning"
	StatusFailed   = "failed"
	StatusDone     = "done"
)

// Server publishes a scan result over HTTP and HTTPS.
// It answers on every host name: the Host header is never checked and the
// HTTPS listener presents the same certificate for any SNI value.
//
// The server is meant to start before the scan: every endpoint answers 200
// from the beginning (so platform health checks pass), returning a status
// document while scanning or after a failure, and the reports once
// SetResult has been called.
type Server struct {
	HTTPAddr  string
	HTTPSAddr string

	// CertFile and KeyFile are optional. When empty, a self-signed
	// certificate is generated at startup.
	CertFile string
	KeyFile  string

	mu        sync.RWMutex
	status    []byte
	jsonData  []byte
	sarifData []byte
	fullData  []byte
}

// NewServer prepares a server for a scan of imageName that is in progress
func NewServer(imageName string) *Server {
	s := &Server{
		HTTPAddr:  DefaultHTTPAddr,
		HTTPSAddr: DefaultHTTPSAddr,
	}
	s.setStatus(imageName, StatusScanning, "")
	return s
}

// SetResult makes the reports for a finished scan available: result at /
// and /sarif, and full (all findings, before triage) at /full.
func (s *Server) SetResult(result, full *models.ScanResult) error {
	jsonData, err := NewJSONReporter(true).Generate(result)
	if err != nil {
		return fmt.Errorf("failed to build JSON report: %w", err)
	}
	fullData, err := NewJSONReporter(true).Generate(full)
	if err != nil {
		return fmt.Errorf("failed to build full JSON report: %w", err)
	}
	sarifData, err := NewSARIFReporter().Generate(result)
	if err != nil {
		return fmt.Errorf("failed to build SARIF report: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.jsonData = jsonData
	s.sarifData = sarifData
	s.fullData = fullData
	return nil
}

// SetError records that the scan of imageName failed
func (s *Server) SetError(imageName string, scanErr error) {
	s.setStatus(imageName, StatusFailed, scanErr.Error())
}

func (s *Server) setStatus(imageName, status, errMsg string) {
	data, _ := json.MarshalIndent(map[string]string{
		"status": status,
		"image":  imageName,
		"error":  errMsg,
	}, "", "  ")

	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = data
}

func (s *Server) handler() http.Handler {
	serve := func(contentType string, report func() []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			body := report()
			if body == nil {
				contentType, body = "application/json", s.status
			}
			s.mu.RUnlock()

			w.Header().Set("Content-Type", contentType)
			w.Write(body)
		}
	}
	sarif := serve("application/sarif+json", func() []byte { return s.sarifData })

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/sarif", sarif)
	mux.HandleFunc("/full", serve("application/json", func() []byte { return s.fullData }))
	mux.HandleFunc("/dockerscan-report.sarif", sarif)
	// Catch-all: any other path returns the full JSON report
	mux.HandleFunc("/", serve("application/json", func() []byte { return s.jsonData }))
	return mux
}

// ListenAndServe serves on both addresses until ctx is cancelled or a
// listener fails.
func (s *Server) ListenAndServe(ctx context.Context) error {
	cert, err := s.certificate()
	if err != nil {
		return err
	}

	handler := s.handler()
	httpSrv := &http.Server{
		Addr:              s.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	httpsSrv := &http.Server{
		Addr:              s.HTTPSAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Same certificate regardless of the requested server name
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
		},
	}

	errCh := make(chan error, 2)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	go func() { errCh <- httpsSrv.ListenAndServeTLS("", "") }()

	select {
	case <-ctx.Done():
		err = nil
	case err = <-errCh:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
	httpsSrv.Shutdown(shutdownCtx)

	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) certificate() (tls.Certificate, error) {
	if s.CertFile != "" || s.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		return cert, nil
	}
	return selfSignedCertificate()
}

// selfSignedCertificate creates an in-memory certificate not bound to any
// domain, so clients connecting under any host name get the same cert.
func selfSignedCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate TLS key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate certificate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dockerscan"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
