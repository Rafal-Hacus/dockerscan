package triage

import (
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func cve(id string, sev models.Severity, verified bool) models.Finding {
	return models.Finding{
		ID: id, Severity: sev, Category: "Vulnerabilities",
		Metadata: map[string]interface{}{"vendor_verified": verified},
	}
}

func secret(secretType, file string) models.Finding {
	return models.Finding{
		ID: "SECRET-" + secretType, Severity: models.SeverityMedium, Category: "Secrets",
		Location: &models.Location{File: file, Line: 1},
		Metadata: map[string]interface{}{"secret_type": secretType},
	}
}

func ids(findings []models.Finding) map[string]int {
	out := make(map[string]int)
	for _, f := range findings {
		key := f.ID
		if f.Location != nil {
			key += "@" + f.Location.File
		}
		out[key]++
	}
	return out
}

func TestFilter(t *testing.T) {
	findings := []models.Finding{
		// CVEs: verified HIGH kept once (duplicate dropped); unverified, MEDIUM and LOW dropped
		cve("CVE-1-openssl", models.SeverityHigh, true),
		cve("CVE-1-openssl", models.SeverityHigh, true),
		cve("CVE-2-libcap2", models.SeverityCritical, false),
		cve("CVE-3-curl", models.SeverityMedium, true),
		cve("CVE-4-sed", models.SeverityLow, true),

		// Secrets: real token in app code kept; certificates and packaged files dropped
		secret("GITHUB_TOKEN", "app/config.env"),
		secret("OPENSSH_PRIVATE_KEY", "root/.ssh/id_rsa"),
		secret("CERTIFICATE", "app/server.crt"),
		secret("TWILIO_SID", "etc/ssl/certs/ca-certificates.crt"),
		secret("TWILIO_SID", "/etc/apt/trusted.gpg.d/debian.asc"),
		secret("BEARER_TOKEN", "usr/share/zsh/vendor-completions/_curl"),

		// CIS: hardening advice dropped; exploitable HIGH kept
		{ID: "CIS-4.1", Severity: models.SeverityHigh, Category: "CIS-Benchmark"},
		{ID: "CIS-4.10", Severity: models.SeverityCritical, Category: "CIS-Benchmark"},
		{ID: "CIS-WORLD-WRITABLE", Severity: models.SeverityHigh, Category: "CIS-Benchmark"},
		{ID: "CIS-SENSITIVE-FILES", Severity: models.SeverityMedium, Category: "CIS-Benchmark"},

		// Supply chain: private example IP dropped; public IP and miners kept
		{ID: "SUPPLY-CHAIN-006", Severity: models.SeverityHigh, Category: "Supply-Chain",
			Location: &models.Location{File: "etc/ssl/openssl.cnf"},
			Metadata: map[string]interface{}{"pattern": "suspicious_ip", "match": "http://192.168.1.1"}},
		{ID: "SUPPLY-CHAIN-006", Severity: models.SeverityHigh, Category: "Supply-Chain",
			Location: &models.Location{File: "app/run.sh"},
			Metadata: map[string]interface{}{"pattern": "suspicious_ip", "match": "http://45.9.148.1"}},
		{ID: "SUPPLY-CHAIN-001", Severity: models.SeverityCritical, Category: "Supply-Chain",
			Location: &models.Location{File: "usr/bin/xmrig"}},

		// Runtime: INFO dropped
		{ID: "RUNTIME-NO-CONTAINERS", Severity: models.SeverityInfo, Category: "Runtime-Security"},
	}

	got := ids(Filter(findings))
	want := map[string]int{
		"CVE-1-openssl":                               1,
		"SECRET-GITHUB_TOKEN@app/config.env":          1,
		"SECRET-OPENSSH_PRIVATE_KEY@root/.ssh/id_rsa": 1,
		"CIS-WORLD-WRITABLE":                          1,
		"SUPPLY-CHAIN-006@app/run.sh":                 1,
		"SUPPLY-CHAIN-001@usr/bin/xmrig":              1,
	}

	if len(got) != len(want) {
		t.Errorf("got %d distinct findings, want %d: %v", len(got), len(want), got)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s: got %d, want %d", k, got[k], n)
		}
	}
}

func TestApplyRecomputesSummary(t *testing.T) {
	full := &models.ScanResult{
		Findings: []models.Finding{
			cve("CVE-1-openssl", models.SeverityHigh, true),
			cve("CVE-1-openssl", models.SeverityHigh, true),
			cve("CVE-2-libcap2", models.SeverityCritical, false),
		},
		Metadata: map[string]string{"version": "test"},
	}

	got := Apply(full)

	if got.Summary.TotalFindings != 1 || got.Summary.BySeverity[models.SeverityHigh] != 1 {
		t.Errorf("summary = %+v", got.Summary)
	}
	if got.Metadata["hidden_findings"] != "2" || got.Metadata["version"] != "test" {
		t.Errorf("metadata = %v", got.Metadata)
	}
	if len(full.Findings) != 3 || full.Metadata["view"] != "" {
		t.Error("Apply modified the full result")
	}
}

func TestOnlyInternalIPs(t *testing.T) {
	cases := map[string]bool{
		"http://192.168.1.1":     true,
		"10.0.0.5 and 127.0.0.1": true,
		"http://45.9.148.1":      false,
		"192.168.1.1, 8.8.8.8":   false,
		"no ip here":             false,
	}
	for in, want := range cases {
		if got := onlyInternalIPs(in); got != want {
			t.Errorf("onlyInternalIPs(%q) = %v, want %v", in, got, want)
		}
	}
}
