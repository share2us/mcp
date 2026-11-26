// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package preflight

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	clicore "github.com/share2us/cli-core"
)

// Share2Us's own credentials. gitleaks has no rules for them, so without these an
// agent could upload a Share2Us login (or paste one into share_text) and the
// scanner would call it clean. Both formats are minted server-side as
// prefix + base64.RawURLEncoding(random bytes):
//
//   - personal access token: "s2u_pat_" + 20 random bytes -> 27 chars
//   - device-session token:  "s2s_"     + 32 random bytes -> 43 chars
//
// Matches are HARD blocks, the same as the gitleaks high-confidence rules.
var share2usTokenRules = []struct {
	id          string
	description string
	re          *regexp.Regexp
	minBody     int
	prefixLen   int
}{
	{
		id:          "share2us-personal-access-token",
		description: "Share2Us personal access token",
		re:          regexp.MustCompile(`s2u_pat_[A-Za-z0-9_-]{27,}`),
		minBody:     27,
		prefixLen:   len("s2u_pat_"),
	},
	{
		id:          "share2us-device-session-token",
		description: "Share2Us device-session token",
		re:          regexp.MustCompile(`s2s_[A-Za-z0-9_-]{43,}`),
		minBody:     43,
		prefixLen:   len("s2s_"),
	},
}

// looksRandom rejects identifier-like bodies (snake_case words, all one case) so
// a long variable name such as s2s_connection_pool_... never trips the rule: the
// body must mix at least two of upper case, lower case and digits. A real token
// body is random base64url, and the chance that 27+ random chars draw from only
// one of those classes is negligible.
func looksRandom(body string) bool {
	var upper, lower, digit bool
	for _, r := range body {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	return countTrue(upper, lower, digit) >= 2
}

func countTrue(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// share2usTokenFindings scans content for Share2Us tokens. It runs over raw bytes
// (binary files included), because unlike gitleaks there is no reason to skip a
// file just because it is not UTF-8: the token is plain ASCII wherever it sits.
func share2usTokenFindings(content []byte) []Finding {
	text := string(content)
	var findings []Finding
	for _, rule := range share2usTokenRules {
		for _, loc := range rule.re.FindAllStringIndex(text, -1) {
			body := text[loc[0]+rule.prefixLen : loc[1]]
			if len(body) < rule.minBody || !looksRandom(body) {
				continue
			}
			findings = append(findings, Finding{
				Kind:       "secret",
				Severity:   "hard",
				Message:    rule.description,
				Line:       strings.Count(text[:loc[0]], "\n") + 1,
				MatchLabel: rule.id,
			})
			break // one finding per rule is enough to block
		}
	}
	return findings
}

// share2usTokenFindingsFile reads up to the scanner's byte cap and scans it.
func share2usTokenFindingsFile(path string) []Finding {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, clicore.DefaultSecretScanMaxBytes))
	if err != nil {
		return nil
	}
	return share2usTokenFindings(content)
}

// HighConfidenceSecret reports the rule ID of the first hard-block secret in an
// in-memory payload (share_text, share_file, publish_artifact), or "" when there
// is none. It combines the gitleaks high-confidence rules with the Share2Us token
// rules, so every agent upload path applies the same hard blocks as a file
// preflight.
func HighConfidenceSecret(data []byte) string {
	if f := share2usTokenFindings(data); len(f) > 0 {
		return f[0].MatchLabel
	}
	if scan, err := clicore.ScanBytesForSecrets(data, clicore.SecretScanOptions{}); err == nil {
		for _, f := range scan.Findings {
			if f.HighConfidence {
				return f.RuleID
			}
		}
	}
	return ""
}

// share2usSecretFiles are the files under the Share2Us config directory that hold
// credentials or key material (see cli-core): the saved login (token + device
// private keys), the LAN identity private key, retained share content keys, and
// the daemon control token.
var share2usSecretFiles = []string{
	"credentials.json",
	"lan_identity.json",
	"pending_reseal.json",
	"daemon.token",
}

// share2usConfigBases lists every directory cli-core may keep its share2us/ config
// dir under, on any OS: os.UserConfigDir (XDG_CONFIG_HOME or ~/.config on Linux,
// ~/Library/Application Support on macOS, %AppData% on Windows) plus the legacy
// pre-2026-07 location XDG_CONFIG_HOME / ~/.config, which on Windows is
// %USERPROFILE%\.config and which cli-core's LoadCredential still reads.
func share2usConfigBases() []string {
	var bases []string
	if dir, err := os.UserConfigDir(); err == nil {
		bases = append(bases, dir)
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		bases = append(bases, xdg)
	}
	if appData := os.Getenv("APPDATA"); appData != "" {
		bases = append(bases, appData)
	}
	if home, err := os.UserHomeDir(); err == nil {
		bases = append(bases,
			filepath.Join(home, ".config"),
			filepath.Join(home, "Library", "Application Support"),
			filepath.Join(home, "AppData", "Roaming"),
		)
	}
	return bases
}

// protectedCredentialPaths returns the absolute paths of every known Share2Us
// secret file, each both as written and with symlinks resolved (when it exists).
func protectedCredentialPaths() []string {
	var out []string
	for _, base := range share2usConfigBases() {
		for _, name := range share2usSecretFiles {
			p := filepath.Join(base, "share2us", name)
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
			out = append(out, p)
			if resolved, err := filepath.EvalSymlinks(p); err == nil && resolved != p {
				out = append(out, resolved)
			}
		}
	}
	return out
}

// normalizePath makes a path comparable across OS conventions: forward slashes,
// no trailing slash, lower case. Comparison is case-insensitive on purpose:
// Windows and default macOS filesystems are case-insensitive, so
// C:\Users\X\AppData\Roaming\Share2Us\Credentials.JSON is the same file.
func normalizePath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimRight(p, "/")
	return strings.ToLower(p)
}

// isShare2UsSecretPath is the pure path test: path is one of the protected paths,
// or is any known secret file sitting directly in a directory named share2us
// (a copied or relocated config dir, a test-isolated XDG_CONFIG_HOME, a backup).
func isShare2UsSecretPath(path string, protected []string) bool {
	norm := normalizePath(path)
	for _, p := range protected {
		if norm == normalizePath(p) {
			return true
		}
	}
	parts := strings.Split(norm, "/")
	if len(parts) < 2 || parts[len(parts)-2] != "share2us" {
		return false
	}
	base := parts[len(parts)-1]
	for _, name := range share2usSecretFiles {
		if base == name {
			return true
		}
	}
	return false
}

// credentialPathFindings HARD-blocks the Share2Us CLI's own credential files. The
// path must already be canonical (absolute, symlinks resolved). os.SameFile also
// catches a hard link or any other alias of a protected file that path matching
// cannot see.
func credentialPathFindings(canonical string) []Finding {
	protected := protectedCredentialPaths()
	hit := isShare2UsSecretPath(canonical, protected)
	if !hit {
		if target, err := os.Stat(canonical); err == nil {
			for _, p := range protected {
				if info, err := os.Stat(p); err == nil && os.SameFile(target, info) {
					hit = true
					break
				}
			}
		}
	}
	if !hit {
		return nil
	}
	return []Finding{{
		Kind:       "prohibited_name",
		Severity:   "hard",
		Message:    "the Share2Us CLI credential and key files cannot be uploaded through MCP",
		MatchLabel: filepath.Base(canonical),
	}}
}
