// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	clicore "github.com/share2us/cli-core"
)

// shareFile creates a share from client-supplied bytes (base64), never touching the
// server filesystem. It is the hosted/remote counterpart to share2us_upload_file
// (which reads a local path): a ChatGPT or other remote client that holds a file's
// bytes — an uploaded document, a generated report — can share it directly.
//
// Like a .mdx local upload, a name ending in .mdx with valid <Form>/<Question>/
// <Choice> content becomes an interactive form (the server derives content_class
// from the name + content_type).
func (s *Server) shareFile(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	var args struct {
		Name        string `json:"name"`
		ContentType string `json:"content_type"`
		DataBase64  string `json:"data_base64"`
		ExpiresIn   string `json:"expires_in"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(args.Name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	encoded := strings.TrimSpace(args.DataBase64)
	if encoded == "" {
		return nil, errors.New("data_base64 is required")
	}
	data, err := decodeBase64Flexible(encoded)
	if err != nil {
		return nil, fmt.Errorf("data_base64 is not valid base64: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("data_base64 decoded to zero bytes")
	}
	// Same secret guard as share_text (AGENTS.md #7): never let an agent exfiltrate a
	// high-confidence secret through the share path.
	if scan, err := clicore.ScanBytesForSecrets(data, clicore.SecretScanOptions{}); err == nil {
		for _, f := range scan.Findings {
			if f.HighConfidence {
				return nil, fmt.Errorf("refused: the file contains a high-confidence secret (%s) and cannot be shared through MCP", f.RuleID)
			}
		}
	}
	contentType := strings.TrimSpace(args.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	expiresIn := strings.TrimSpace(args.ExpiresIn)
	if expiresIn == "" {
		expiresIn = "24h"
	}
	contentClass := clicore.ContentClassForNameAndType(name, contentType)
	sum := sha256String(string(data))
	return uploadBytes(ctx, client, s.recipientBase, name, contentType, contentClass, expiresIn, sum, "", uint64(len(data)), func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

// decodeBase64Flexible accepts std/raw-std/url/raw-url base64.
func decodeBase64Flexible(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("not base64 (tried std/raw/url)")
}
