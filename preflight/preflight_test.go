// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretClassification(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		protection Protection
		status     SecretStatus
	}{
		{name: "id_rsa", body: "not even needed", protection: ProtectionHard, status: SecretStatusBlock},
		{name: "service-account-prod.json", body: `{}`, protection: ProtectionHard, status: SecretStatusBlock},
		{name: "vault.kdbx", body: "binary", protection: ProtectionHard, status: SecretStatusBlock},
		{name: ".env", body: "NAME=value", protection: ProtectionSoft, status: SecretStatusWarn},
		// An AWS access-key ID in content is now HARD (was soft) — the whole point
		// of routing the agent path through the real scanner: the agent can no
		// longer override_soft_block past a real credential.
		{name: "notes.txt", body: "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", protection: ProtectionHard, status: SecretStatusBlock},
		// A generic api_key= assignment stays SOFT (higher false-positive rate).
		{name: "config.txt", body: `service_api_key = "abcd1234efgh5678ijkl9012mnop3456"`, protection: ProtectionSoft, status: SecretStatusWarn},
		{name: "readme.txt", body: "hello world, nothing to see here", protection: ProtectionNone, status: SecretStatusClean},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.name)
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := Build(path)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if result.Protection != tt.protection || result.SecretScan.Status != tt.status {
				t.Fatalf("protection/status = %s/%s", result.Protection, result.SecretScan.Status)
			}
		})
	}
}

func TestPrivateKeyContentHardBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-secret.txt")
	if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Build(path)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if result.Protection != ProtectionHard {
		t.Fatalf("protection = %s", result.Protection)
	}
}
