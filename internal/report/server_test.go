package report

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func TestServerServesReportsForAnyHost(t *testing.T) {
	srv, err := NewServer(&models.ScanResult{Target: models.ScanTarget{ImageName: "nginx:latest"}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cases := []struct {
		host, path, contentType, body string
	}{
		{"example.com", "/", "application/json", "nginx:latest"},
		{"10.0.0.1", "/anything", "application/json", "nginx:latest"},
		{"other.test", "/sarif", "application/sarif+json", "\"version\": \"2.1.0\""},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", "http://"+tc.host+tc.path, nil)
		rec := httptest.NewRecorder()
		srv.handler.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Errorf("%s%s: status %d", tc.host, tc.path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != tc.contentType {
			t.Errorf("%s%s: content type %q, want %q", tc.host, tc.path, got, tc.contentType)
		}
		if !strings.Contains(rec.Body.String(), tc.body) {
			t.Errorf("%s%s: body missing %q", tc.host, tc.path, tc.body)
		}
	}
}

func TestSelfSignedCertificate(t *testing.T) {
	cert, err := selfSignedCertificate()
	if err != nil {
		t.Fatalf("selfSignedCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("certificate or key missing")
	}
}
