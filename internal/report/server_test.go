package report

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func get(t *testing.T, srv *Server, host, path string) (string, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+path, nil)
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("%s%s: status %d, want 200", host, path, rec.Code)
	}
	return rec.Header().Get("Content-Type"), rec.Body.String()
}

func TestServerAnswersWhileScanning(t *testing.T) {
	srv := NewServer("nginx:latest")

	for _, path := range []string{"/", "/sarif"} {
		ct, body := get(t, srv, "example.com", path)
		if ct != "application/json" || !strings.Contains(body, `"status": "scanning"`) {
			t.Errorf("%s: got %q %q, want scanning status", path, ct, body)
		}
	}
	if _, body := get(t, srv, "example.com", "/healthz"); body != "ok\n" {
		t.Errorf("/healthz: got %q", body)
	}
}

func TestServerServesReportsForAnyHost(t *testing.T) {
	srv := NewServer("nginx:latest")
	if err := srv.SetResult(&models.ScanResult{Target: models.ScanTarget{ImageName: "nginx:latest"}}); err != nil {
		t.Fatalf("SetResult: %v", err)
	}

	cases := []struct {
		host, path, contentType, body string
	}{
		{"example.com", "/", "application/json", `"ImageName": "nginx:latest"`},
		{"10.0.0.1", "/anything", "application/json", `"ImageName": "nginx:latest"`},
		{"other.test", "/sarif", "application/sarif+json", `"version": "2.1.0"`},
	}
	for _, tc := range cases {
		ct, body := get(t, srv, tc.host, tc.path)
		if ct != tc.contentType {
			t.Errorf("%s%s: content type %q, want %q", tc.host, tc.path, ct, tc.contentType)
		}
		if !strings.Contains(body, tc.body) {
			t.Errorf("%s%s: body missing %q:\n%s", tc.host, tc.path, tc.body, body)
		}
	}
}

func TestServerReportsScanError(t *testing.T) {
	srv := NewServer("nginx:latest")
	srv.SetError("nginx:latest", errors.New("cannot connect to the Docker daemon"))

	_, body := get(t, srv, "example.com", "/")
	if !strings.Contains(body, `"status": "failed"`) || !strings.Contains(body, "Docker daemon") {
		t.Errorf("got %q, want failed status with error", body)
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
