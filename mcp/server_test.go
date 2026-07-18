package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
}

func (f *fakeClient) CreateUpload(context.Context, clicore.UploadCreateRequest) (clicore.UploadCreateResponse, error) {
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
