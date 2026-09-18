// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clicore "github.com/share2us/cli-core"
	"github.com/share2us/mcp/preflight"
)

func TestToolsListSchema(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	if err := testServer(&fakeClient{}).Serve(t.Context(), in, &out); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	var resp struct {
		Result struct {
			Tools []ToolDescriptor `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Result.Tools) != 9 {
		t.Fatalf("tools = %d", len(resp.Result.Tools))
	}
	if resp.Result.Tools[0].Name != "share2us_preview_file" {
		t.Fatalf("first tool = %s", resp.Result.Tools[0].Name)
	}
}

func TestEnvRecipientBase(t *testing.T) {
	t.Setenv("SHARE2US_SHARE_BASE_URL", " https://s.staging.example.test/ ")

	if got := envRecipientBase(); got != "https://s.staging.example.test" {
		t.Fatalf("envRecipientBase() = %q", got)
	}
}

func TestDisabledToolsAreOmittedAndUndispatchable(t *testing.T) {
	server := NewServer(
		WithDisabledTools("share2us_preview_file"),
		WithCredentialLoader(func() (clicore.Credential, error) {
			return clicore.Credential{APIBase: "https://api.example.test", Token: "s2s_test"}, nil
		}),
		WithClientFactory(func(clicore.Credential) Client { return &fakeClient{} }),
	)

	list := server.handle(t.Context(), rpcRequest{ID: mustRaw(`1`), Method: "tools/list"})
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal list response: %v", err)
	}
	if strings.Contains(string(raw), "share2us_preview_file") {
		t.Fatalf("disabled tool appeared in tools/list: %s", raw)
	}

	call := server.handle(t.Context(), rpcRequest{
		ID:     mustRaw(`2`),
		Method: "tools/call",
		Params: mustRaw(`{"name":"share2us_preview_file","arguments":{"path":"/etc/passwd"}}`),
	})
	if call.Error == nil || !strings.Contains(call.Error.Message, "unknown tool") {
		t.Fatalf("call response = %+v, want unknown tool error", call)
	}
}

func TestStdioSmokeInitializeThenToolsList(t *testing.T) {
	input := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n",
	)
	var out bytes.Buffer
	if err := testServer(&fakeClient{}).Serve(t.Context(), input, &out); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("responses = %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[1], "share2us_get_plan_limits") {
		t.Fatalf("tools/list response missing tool: %s", lines[1])
	}
}

func TestPreviewBuildingWithFakeClient(t *testing.T) {
	server := testServer(&fakeClient{})
	result, err := server.previewFile(t.Context(), mustRaw(`{"path":"file.txt"}`))
	if err != nil {
		t.Fatalf("previewFile() error = %v", err)
	}
	preview := result.(preflight.Result)
	if preview.CanonicalPath != "/tmp/file.txt" || preview.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("preview = %+v", preview)
	}
}

func TestUploadRefusesWithoutConfirm(t *testing.T) {
	server := testServer(&fakeClient{})
	_, err := server.uploadFile(t.Context(), mustRaw(`{"path":"file.txt"}`))
	if err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatalf("error = %v, want confirm refusal", err)
	}
}

func TestUploadHardBlockRefuses(t *testing.T) {
	server := testServer(&fakeClient{previewProtection: preflight.ProtectionHard})
	if _, err := server.previewFile(t.Context(), mustRaw(`{"path":"file.txt"}`)); err != nil {
		t.Fatalf("previewFile() error = %v", err)
	}
	_, err := server.uploadFile(t.Context(), mustRaw(`{"path":"file.txt","confirm":true}`))
	if err == nil || !strings.Contains(err.Error(), "hard-blocked") {
		t.Fatalf("error = %v, want hard block", err)
	}
}

// share_text used to upload with no scan at all. It must now refuse a
// high-confidence secret (private key) before any upload call.
func TestShareTextRefusesSecret(t *testing.T) {
	server := testServer(&fakeClient{})
	body := `{"text":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n-----END OPENSSH PRIVATE KEY-----\n"}`
	_, err := server.shareText(t.Context(), mustRaw(body))
	if err == nil || !strings.Contains(err.Error(), "high-confidence secret") {
		t.Fatalf("error = %v, want high-confidence secret refusal", err)
	}
}

// Ordinary text still shares fine (no false positive).
func TestShareTextAllowsCleanText(t *testing.T) {
	server := testServer(&fakeClient{})
	if _, err := server.shareText(t.Context(), mustRaw(`{"text":"hello, this is a normal note"}`)); err != nil {
		t.Fatalf("shareText() clean error = %v", err)
	}
}

func testServer(client *fakeClient) *Server {
	return NewServer(
		WithCredentialLoader(func() (clicore.Credential, error) {
			return clicore.Credential{APIBase: "https://api.example.test", Token: "s2s_test"}, nil
		}),
		WithClientFactory(func(clicore.Credential) Client { return client }),
		WithPreviewBuilder(func(path string) (preflight.Result, error) {
			protection := client.previewProtection
			status := preflight.SecretStatusClean
			if protection == preflight.ProtectionHard {
				status = preflight.SecretStatusBlock
			}
			if protection == preflight.ProtectionSoft {
				status = preflight.SecretStatusWarn
			}
			return preflight.Result{
				CanonicalPath:            "/tmp/" + path,
				Filename:                 path,
				SizeBytes:                5,
				SHA256:                   strings.Repeat("a", 64),
				ContentType:              "text/plain; charset=utf-8",
				ContentClass:             "text",
				RequestedExpiry:          "24h",
				PlanEligible:             true,
				SecretScan:               preflight.SecretScan{Status: status},
				Protection:               protection,
				RequiresUserConfirmation: true,
			}, nil
		}),
	)
}

type fakeClient struct {
	previewProtection preflight.Protection
	// lastCreate records what was actually sent, so a test can assert on the
	// request rather than only on the reply.
	lastCreate clicore.UploadCreateRequest
}

func (f *fakeClient) CreateUpload(_ context.Context, req clicore.UploadCreateRequest) (clicore.UploadCreateResponse, error) {
	f.lastCreate = req
	return clicore.UploadCreateResponse{
		Upload:          clicore.PresignedUpload{URL: "https://upload.example.test", Method: "PUT"},
		Share:           clicore.ShareRef{PublicID: "pub-1"},
		UploadSessionID: "upload-1",
		ExpiresAt:       "2026-07-04T00:00:00Z",
	}, nil
}

func (f *fakeClient) PutUpload(context.Context, clicore.PresignedUpload, io.Reader, int64) error {
	return nil
}

func (f *fakeClient) CompleteUpload(context.Context, string) (clicore.UploadCompleteResponse, error) {
	return clicore.UploadCompleteResponse{PublicID: "pub-1", Status: "ready", ExpiresAt: "2026-07-04T00:00:00Z"}, nil
}

func (f *fakeClient) ListShares(context.Context) (clicore.ListSharesResponse, error) {
	return clicore.ListSharesResponse{Shares: []clicore.Share{{PublicID: "pub-1", FileName: "a.txt"}}}, nil
}

func (f *fakeClient) RevokeShare(context.Context, string) (clicore.Share, error) {
	return clicore.Share{PublicID: "pub-1", Status: "revoked"}, nil
}

func (f *fakeClient) ExtendExpiry(context.Context, string, time.Duration) (clicore.Share, error) {
	return clicore.Share{PublicID: "pub-1", Status: "ready"}, nil
}

func (f *fakeClient) Usage(context.Context) (clicore.UsageResponse, error) {
	return clicore.UsageResponse{StorageQuotaBytes: 100, MaxActiveShares: 10}, nil
}

func mustRaw(value string) json.RawMessage {
	return json.RawMessage(value)
}

// Re-sharing the same file through MCP must keep its link.
//
// The server dedups on source_ref (sha256 of the canonical path). The CLI has
// always sent it; MCP sent nothing, so every agent re-share of the same file
// minted a NEW public id and the link changed underneath the user. A text share
// has no file behind it and must still send nothing, so pasted text stays
// genuinely new each time.
func TestUploadSendsSourceRefSoResharesKeepTheirLink(t *testing.T) {
	client := &fakeClient{}
	server := testServer(client)

	// The harness builds CanonicalPath as "/tmp/"+path, and the upload really
	// opens it, so the file has to exist there. 5 bytes to match the fake's
	// SizeBytes.
	name := fmt.Sprintf("s2u-srcref-%d.txt", time.Now().UnixNano())
	full := filepath.Join("/tmp", name)
	if err := os.WriteFile(full, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(full) })
	args := mustRaw(fmt.Sprintf(`{"path":%q,"confirm":true}`, name))

	if _, err := server.previewFile(t.Context(), mustRaw(fmt.Sprintf(`{"path":%q}`, name))); err != nil {
		t.Fatalf("previewFile() error = %v", err)
	}
	if _, err := server.uploadFile(t.Context(), args); err != nil {
		t.Fatalf("uploadFile() error = %v", err)
	}
	want, _, err := clicore.SourceRefForPath(full)
	if err != nil {
		t.Fatalf("SourceRefForPath() error = %v", err)
	}
	if client.lastCreate.SourceRef != want {
		t.Errorf("file share SourceRef = %q, want %q (sha256 of the canonical path)",
			client.lastCreate.SourceRef, want)
	}

	// A second share of the same path sends the SAME ref, which is what lets the
	// server resolve it to the existing share instead of creating another.
	first := client.lastCreate.SourceRef
	if _, err := server.uploadFile(t.Context(), args); err != nil {
		t.Fatalf("second uploadFile() error = %v", err)
	}
	if client.lastCreate.SourceRef != first {
		t.Errorf("re-share SourceRef = %q, want the same %q", client.lastCreate.SourceRef, first)
	}
}

func TestShareTextSendsNoSourceRef(t *testing.T) {
	client := &fakeClient{}
	server := testServer(client)
	if _, err := server.shareText(t.Context(), mustRaw(`{"text":"just some notes","confirm":true}`)); err != nil {
		t.Fatalf("shareText() error = %v", err)
	}
	if client.lastCreate.SourceRef != "" {
		t.Errorf("text share SourceRef = %q, want empty (no file behind it)", client.lastCreate.SourceRef)
	}
}
