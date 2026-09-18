// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package preflight

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	clicore "github.com/share2us/cli-core"
)

type Protection string

const (
	ProtectionNone Protection = "none"
	ProtectionSoft Protection = "soft_block"
	ProtectionHard Protection = "hard_block"
)

type SecretStatus string

const (
	SecretStatusClean SecretStatus = "clean"
	SecretStatusWarn  SecretStatus = "warning"
	SecretStatusBlock SecretStatus = "blocked"
)

type Finding struct {
	Kind       string `json:"kind"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Line       int    `json:"line,omitempty"`
	MatchLabel string `json:"match_label,omitempty"`
}

type SecretScan struct {
	Status   SecretStatus `json:"status"`
	Findings []Finding    `json:"findings"`
}

type Result struct {
	CanonicalPath            string     `json:"canonical_path"`
	Filename                 string     `json:"filename"`
	SizeBytes                uint64     `json:"size_bytes"`
	SHA256                   string     `json:"sha256"`
	ContentType              string     `json:"content_type"`
	ContentClass             string     `json:"content_class"`
	RequestedExpiry          string     `json:"requested_expiry"`
	PlanEligible             bool       `json:"plan_eligible"`
	SecretScan               SecretScan `json:"secret_scan"`
	Protection               Protection `json:"protection"`
	RequiresUserConfirmation bool       `json:"requires_user_confirmation"`
}

func Build(path string) (Result, error) {
	if strings.TrimSpace(path) == "" {
		return Result{}, fmt.Errorf("path is required")
	}
	canonical, err := canonicalPath(path)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return Result{}, err
	}
	if info.IsDir() {
		return Result{}, fmt.Errorf("cannot preview a directory")
	}
	file, err := os.Open(canonical)
	if err != nil {
		return Result{}, err
	}
	defer file.Close()

	hash := sha256.New()
	var sample bytes.Buffer
	tee := io.TeeReader(file, hash)
	if _, err := io.Copy(&sample, io.LimitReader(tee, 1024*1024)); err != nil {
		return Result{}, err
	}
	if _, err := io.Copy(hash, tee); err != nil {
		return Result{}, err
	}

	filename := filepath.Base(canonical)
	contentType := detectContentType(filename, sample.Bytes())
	findings := prohibitedNameFindings(filename)
	findings = append(findings, secretScanFindings(canonical)...)
	secretScan := scanFromFindings(findings)
	protection := protectionFromFindings(findings)

	return Result{
		CanonicalPath:            canonical,
		Filename:                 filename,
		SizeBytes:                uint64(info.Size()),
		SHA256:                   hex.EncodeToString(hash.Sum(nil)),
		ContentType:              contentType,
		ContentClass:             contentClass(filename, contentType),
		RequestedExpiry:          "24h",
		PlanEligible:             true,
		SecretScan:               secretScan,
		Protection:               protection,
		RequiresUserConfirmation: true,
	}, nil
}

func canonicalPath(path string) (string, error) {
	expanded := path
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			expanded = home
		} else if strings.HasPrefix(path, "~/") {
			expanded = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	abs, err := filepath.Abs(expanded)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func detectContentType(name string, sample []byte) string {
	if contentType := mime.TypeByExtension(filepath.Ext(name)); contentType != "" {
		return contentType
	}
	if len(sample) == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(sample)
}

func contentClass(name, contentType string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	// Markdown BEFORE the text/ prefix, because text/markdown matches that prefix
	// and would otherwise be reported as plain "text". The server keys its preview
	// on the class alone, so a .md sent as "text" rendered unformatted -- every
	// markdown file an agent shared came out as plain text on the share page.
	case ext == ".md", ext == ".markdown", contentType == "text/markdown":
		return "markdown"
	case strings.HasPrefix(contentType, "text/"), contentType == "application/json", contentType == "application/xml":
		return "text"
	case ext == ".zip" || contentType == "application/zip":
		return "zip"
	default:
		return "binary"
	}
}

func prohibitedNameFindings(filename string) []Finding {
	lower := strings.ToLower(filename)
	var findings []Finding
	add := func(severity, message string) {
		findings = append(findings, Finding{Kind: "prohibited_name", Severity: severity, Message: message, MatchLabel: filename})
	}
	switch {
	case lower == "id_rsa" || lower == "id_ed25519" || strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".p12"):
		add("hard", "private key or SSH key filenames cannot be uploaded through MCP")
	case strings.HasPrefix(lower, "service-account") && strings.HasSuffix(lower, ".json"):
		add("hard", "cloud service-account JSON cannot be uploaded through MCP")
	case strings.HasSuffix(lower, ".kdbx") || strings.Contains(lower, "password") && (strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite")):
		add("hard", "password database files cannot be uploaded through MCP")
	case lower == ".env" || strings.HasPrefix(lower, ".env.") || lower == "credentials.json" || lower == "kubeconfig" || lower == "terraform.tfvars" || strings.HasSuffix(lower, ".tfstate"):
		add("soft", "sensitive configuration filename requires explicit override")
	}
	return findings
}

// secretScanFindings runs the real gitleaks scanner (shared with the CLI) over
// the WHOLE file (up to its 5 MiB cap), not a 1 MiB sample. High-confidence
// credential rules (private keys, cloud/provider tokens) are HARD — the agent
// cannot override them; lower-confidence hits (e.g. generic-api-key) are SOFT.
// A scan error or a binary/non-text file yields no secret findings (the filename
// rules still apply).
func secretScanFindings(path string) []Finding {
	res, err := clicore.ScanFileForSecrets(path, clicore.SecretScanOptions{})
	if err != nil || res.Skipped {
		return nil
	}
	findings := make([]Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		severity := "soft"
		if f.HighConfidence {
			severity = "hard"
		}
		findings = append(findings, Finding{
			Kind:       "secret",
			Severity:   severity,
			Message:    f.Description,
			Line:       f.Line,
			MatchLabel: f.RuleID,
		})
	}
	return findings
}

func scanFromFindings(findings []Finding) SecretScan {
	status := SecretStatusClean
	for _, finding := range findings {
		if finding.Severity == "hard" {
			status = SecretStatusBlock
			break
		}
		if finding.Severity == "soft" {
			status = SecretStatusWarn
		}
	}
	return SecretScan{Status: status, Findings: findings}
}

func protectionFromFindings(findings []Finding) Protection {
	protection := ProtectionNone
	for _, finding := range findings {
		if finding.Severity == "hard" {
			return ProtectionHard
		}
		if finding.Severity == "soft" {
			protection = ProtectionSoft
		}
	}
	return protection
}
