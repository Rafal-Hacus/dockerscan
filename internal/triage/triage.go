// Package triage reduces a scan result to the findings worth investigating:
// those that are plausibly exploitable or need manual verification. It drops
// duplicates, best-practice/hardening advice, public material reported as
// secrets, and CVE matches that rest on a product-name guess.
package triage

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

// hardeningChecks are CIS findings that describe configuration hygiene rather
// than something an attacker can exploit.
var hardeningChecks = map[string]bool{
	"CIS-4.1":           true, // runs as root
	"CIS-4.3":           true, // unnecessary packages
	"CIS-4.3-BLOAT":     true,
	"CIS-4.6":           true, // no HEALTHCHECK
	"CIS-4.7":           true, // latest tag
	"CIS-4.8":           true, // setuid binaries (standard distro set)
	"CIS-4.8-SETGID":    true,
	"CIS-5.7":           true, // privileged ports
	"CIS-SHELL-PRESENT": true,
	"CIS-4.10":          true, // keyword-based secret hits; the secrets scanner covers real ones
}

// packagedPaths hold files installed by the OS package manager. Pattern
// matches inside them (CA bundles, distro signing keys, package metadata,
// docs, shell completions) are public data, not leaked secrets.
var packagedPaths = []string{
	"etc/ssl/certs/",
	"usr/share/ca-certificates/",
	"etc/ca-certificates.conf",
	"etc/apt/trusted.gpg.d/",
	"usr/share/keyrings/",
	"etc/pki/",
	"var/lib/dpkg/",
	"var/lib/apt/",
	"var/lib/rpm/",
	"lib/apk/db/",
	"var/cache/debconf/",
	"usr/share/doc/",
	"usr/share/man/",
	"usr/share/zsh/",
	"usr/share/fish/",
	"usr/share/bash-completion/",
	"usr/share/common-licenses/",
}

var ipPattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// Apply returns a copy of result containing only actionable findings, with
// the summary recomputed. The number of hidden findings is recorded in the
// result metadata.
func Apply(result *models.ScanResult) *models.ScanResult {
	out := *result
	out.Findings = Filter(result.Findings)

	out.Summary = models.Summary{
		TotalFindings: len(out.Findings),
		BySeverity:    make(map[models.Severity]int),
		ByCategory:    make(map[string]int),
	}
	for _, f := range out.Findings {
		out.Summary.BySeverity[f.Severity]++
		out.Summary.ByCategory[f.Category]++
	}

	out.Metadata = make(map[string]string, len(result.Metadata)+2)
	for k, v := range result.Metadata {
		out.Metadata[k] = v
	}
	out.Metadata["view"] = "actionable"
	out.Metadata["hidden_findings"] = fmt.Sprint(len(result.Findings) - len(out.Findings))
	return &out
}

// Filter keeps the findings that are plausibly exploitable, deduplicated.
func Filter(findings []models.Finding) []models.Finding {
	var kept []models.Finding
	seen := make(map[string]bool)

	for _, f := range findings {
		key := dedupeKey(f)
		if seen[key] {
			continue
		}
		seen[key] = true

		if keep(f) {
			kept = append(kept, f)
		}
	}
	return kept
}

func keep(f models.Finding) bool {
	if f.Severity == models.SeverityLow || f.Severity == models.SeverityInfo {
		return false
	}

	switch f.Category {
	case "Vulnerabilities":
		// Name-only matches (vendor unverified) are frequently a different
		// product with a similar name.
		verified, _ := f.Metadata["vendor_verified"].(bool)
		return verified && highOrCritical(f.Severity)

	case "Secrets":
		if f.Metadata["secret_type"] == "CERTIFICATE" {
			return false // certificates are public; private keys have their own types
		}
		return f.Location == nil || !isPackagedPath(f.Location.File)

	case "CIS-Benchmark":
		return !hardeningChecks[f.ID] && highOrCritical(f.Severity)

	case "Supply-Chain":
		if f.Metadata["pattern"] == "suspicious_ip" {
			match, _ := f.Metadata["match"].(string)
			return !onlyInternalIPs(match)
		}
		return true

	default:
		return highOrCritical(f.Severity)
	}
}

func highOrCritical(s models.Severity) bool {
	return s == models.SeverityHigh || s == models.SeverityCritical
}

func isPackagedPath(file string) bool {
	file = strings.TrimPrefix(file, "/")
	for _, p := range packagedPaths {
		if strings.HasPrefix(file, p) {
			return true
		}
	}
	return false
}

// onlyInternalIPs reports whether every IP address in s is private,
// loopback or link-local (e.g. example addresses in default configs).
func onlyInternalIPs(s string) bool {
	ips := ipPattern.FindAllString(s, -1)
	if len(ips) == 0 {
		return false
	}
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			return false
		}
	}
	return true
}

func dedupeKey(f models.Finding) string {
	if f.Location == nil {
		return f.ID
	}
	return fmt.Sprintf("%s|%s|%d", f.ID, f.Location.File, f.Location.Line)
}
