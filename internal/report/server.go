package report

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

const (
	// DefaultHTTPAddr is where results are served over plain HTTP
	DefaultHTTPAddr = ":80"

	// DefaultHTTPSAddr is where results are served over HTTPS
	DefaultHTTPSAddr = ":443"
)

// Server publishes a scan result over HTTP and HTTPS.
// It answers on every host name: the Host header is never checked and the
// HTTPS listener presents the same certificate for any SNI value.
type Server struct {
	HTTPAddr  string
	HTTPSAddr string

	// CertFile and KeyFile are optional. When empty, a self-signed
	// certificate is generated at startup.
	CertFile string
	KeyFile  string

	handler http.Handler
}

// NewServer prepares a server that serves the given result
func NewServer(result *models.ScanResult) (*Server, error) {
	jsonData, err := NewJSONReporter(true).Generate(result)
	if err != nil {
		return nil, fmt.Errorf("failed to build JSON report: %w", err)
	}
	sarifData, err := NewSARIFReporter().Generate(result)
	if err != nil {
		return nil, fmt.Errorf("failed to build SARIF report: %w", err)
	}

	mux := http.NewServeMux()
	serve := func(contentType string, body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.Write(body)
		}
	}
	mux.HandleFunc("/sarif", serve("application/sarif+json", sarifData))
	mux.HandleFunc("/dockerscan-report.sarif", serve("application/sarif+json", sarifData))
	// Catch-all: any other path returns the full JSON report
	mux.HandleFunc("/", serve("application/json", jsonData))

	return &Server{
		HTTPAddr:  DefaultHTTPAddr,
		HTTPSAddr: DefaultHTTPSAddr,
		handler:   mux,
	}, nil
}

// ListenAndServe serves on both addresses until ctx is cancelled or a
// listener fails.
func (s *Server) ListenAndServe(ctx context.Context) error {
	cert, err := s.certificate()
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              s.HTTPAddr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	httpsSrv := &http.Server{
		Addr:              s.HTTPSAddr,
		Handler:           s.handler,
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
