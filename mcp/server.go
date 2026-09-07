// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	clicore "github.com/share2us/cli-core"
	"github.com/share2us/mcp/preflight"
)

const defaultRecipientBase = "https://s.share2.us"

type Client interface {
	CreateUpload(context.Context, clicore.UploadCreateRequest) (clicore.UploadCreateResponse, error)
	PutUpload(context.Context, clicore.PresignedUpload, io.Reader, int64) error
	CompleteUpload(context.Context, string) (clicore.UploadCompleteResponse, error)
	ListShares(context.Context) (clicore.ListSharesResponse, error)
	RevokeShare(context.Context, string) (clicore.Share, error)
	ExtendExpiry(context.Context, string, time.Duration) (clicore.Share, error)
	Usage(context.Context) (clicore.UsageResponse, error)
}

type CredentialLoader func() (clicore.Credential, error)
type HTTPCredentialResolver func(*http.Request) (clicore.Credential, error)
type ClientFactory func(clicore.Credential) Client
type PreviewBuilder func(string) (preflight.Result, error)

type Server struct {
	credentialLoader       CredentialLoader
	httpCredentialResolver HTTPCredentialResolver
	clientFactory          ClientFactory
	previewBuilder         PreviewBuilder
	disabledTools          map[string]bool
	tools                  map[string]Tool
	previews               map[string]preflight.Result
	recipientBase          string
}

type Option func(*Server)

func NewServer(options ...Option) *Server {
	s := &Server{
		credentialLoader: clicore.LoadCredential,
		clientFactory: func(credential clicore.Credential) Client {
			return clicore.NewClient(credential.APIBase, credential.Token)
		},
		previewBuilder: preflight.Build,
		disabledTools:  make(map[string]bool),
		tools:          make(map[string]Tool),
		previews:       make(map[string]preflight.Result),
		recipientBase:  envRecipientBase(),
	}
	for _, option := range options {
		option(s)
	}
	s.registerTools()
	return s
}

func envRecipientBase() string {
	if value := strings.TrimRight(strings.TrimSpace(os.Getenv("SHARE2US_SHARE_BASE_URL")), "/"); value != "" {
		return value
	}
	return defaultRecipientBase
}

func WithCredentialLoader(loader CredentialLoader) Option {
	return func(s *Server) {
		s.credentialLoader = loader
	}
}

func WithHTTPCredentialResolver(resolver HTTPCredentialResolver) Option {
	return func(s *Server) {
		s.httpCredentialResolver = resolver
	}
}

func WithClientFactory(factory ClientFactory) Option {
	return func(s *Server) {
		s.clientFactory = factory
	}
}

func WithPreviewBuilder(builder PreviewBuilder) Option {
	return func(s *Server) {
		s.previewBuilder = builder
	}
}

func WithDisabledTools(names ...string) Option {
	return func(s *Server) {
		if s.disabledTools == nil {
			s.disabledTools = make(map[string]bool)
		}
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" {
				s.disabledTools[name] = true
			}
		}
	}
}

func ServeStdio(ctx context.Context) error {
	return NewServer().Serve(ctx, os.Stdin, os.Stdout)
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	decoder := json.NewDecoder(in)
	encoder := json.NewEncoder(out)
	for {
		var req rpcRequest
		if err := decoder.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		resp := s.handle(ctx, req)
		if req.ID == nil {
			continue
		}
		if err := encoder.Encode(resp); err != nil {
			return err
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(rpcErr(nil, -32600, "method must be POST"))
		return
	}
	if s == nil || s.httpCredentialResolver == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(rpcErr(nil, -32001, "unauthorized"))
		return
	}
	credential, err := s.httpCredentialResolver(r)
	if err != nil || strings.TrimSpace(credential.Token) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(rpcErr(nil, -32001, "unauthorized"))
		return
	}
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(rpcErr(nil, -32700, "parse error"))
		return
	}
	resp := s.handle(withCredential(r.Context(), credential), req)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handle(ctx context.Context, req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcOK(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]string{"name": "share2us-mcp-local", "version": clicore.Version},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		})
	case "tools/list":
		tools := make([]ToolDescriptor, 0, len(toolOrder))
		for _, name := range toolOrder {
			if tool, ok := s.tools[name]; ok {
				tools = append(tools, tool.Descriptor)
			}
		}
		return rpcOK(req.ID, map[string]any{"tools": tools})
	case "tools/call":
		var params toolsCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return rpcErr(req.ID, -32602, "invalid tools/call params")
		}
		tool, ok := s.tools[params.Name]
		if !ok {
			return rpcErr(req.ID, -32602, "unknown tool: "+params.Name)
		}
		result, err := tool.Handler(ctx, params.Arguments)
		if err != nil {
			return rpcOK(req.ID, toolError(err.Error()))
		}
		return rpcOK(req.ID, toolResult(result))
	default:
		return rpcErr(req.ID, -32601, "method not found")
	}
}

type Tool struct {
	Descriptor ToolDescriptor
	Handler    func(context.Context, json.RawMessage) (any, error)
}

type ToolDescriptor struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var toolOrder = []string{
	"share2us_preview_file",
	"share2us_upload_file",
	"share2us_share_text",
	"share2us_list_shares",
	"share2us_get_share",
	"share2us_revoke_share",
	"share2us_extend_expiry",
	"share2us_get_usage",
	"share2us_get_plan_limits",
}

func (s *Server) registerTools() {
	s.registerTool("share2us_preview_file", Tool{Descriptor: descriptor("share2us_preview_file", "Preflight a local file before upload confirmation.", objectSchema(map[string]any{"path": stringSchema()})), Handler: s.previewFile})
	s.registerTool("share2us_upload_file", Tool{Descriptor: descriptor("share2us_upload_file", "Upload a previously previewed local file after explicit confirmation.", objectSchema(map[string]any{"path": stringSchema(), "confirm": boolSchema(), "override_soft_block": boolSchema()})), Handler: s.uploadFile})
	s.registerTool("share2us_share_text", Tool{Descriptor: descriptor("share2us_share_text", "Create a text share.", objectSchema(map[string]any{"text": stringSchema(), "name": stringSchema(), "expires_in": stringSchema()})), Handler: s.shareText})
	s.registerTool("share2us_list_shares", Tool{Descriptor: descriptor("share2us_list_shares", "List shares for the authenticated account.", objectSchema(map[string]any{})), Handler: s.listShares})
	s.registerTool("share2us_get_share", Tool{Descriptor: descriptor("share2us_get_share", "Get a share by public_id from the authenticated account's share list.", objectSchema(map[string]any{"public_id": stringSchema()})), Handler: s.getShare})
	s.registerTool("share2us_revoke_share", Tool{Descriptor: descriptor("share2us_revoke_share", "Revoke a share by public_id.", objectSchema(map[string]any{"public_id": stringSchema()})), Handler: s.revokeShare})
	s.registerTool("share2us_extend_expiry", Tool{Descriptor: descriptor("share2us_extend_expiry", "Extend a share expiry by duration.", objectSchema(map[string]any{"public_id": stringSchema(), "expires_in": stringSchema()})), Handler: s.extendExpiry})
	s.registerTool("share2us_get_usage", Tool{Descriptor: descriptor("share2us_get_usage", "Get usage for the authenticated account.", objectSchema(map[string]any{})), Handler: s.getUsage})
	s.registerTool("share2us_get_plan_limits", Tool{Descriptor: descriptor("share2us_get_plan_limits", "Get plan limits from usage entitlement fields.", objectSchema(map[string]any{})), Handler: s.getPlanLimits})
}

func (s *Server) registerTool(name string, tool Tool) {
	if s.disabledTools[name] {
		return
	}
	s.tools[name] = tool
}

func (s *Server) client(ctx context.Context) (Client, error) {
	if credential, ok := credentialFromContext(ctx); ok && strings.TrimSpace(credential.Token) != "" {
		return s.clientFactory(credential), nil
	}
	credential, err := s.credentialLoader()
	if err != nil || strings.TrimSpace(credential.Token) == "" {
		return nil, errors.New("not logged in; run `share2us login` before using Share2Us MCP tools")
	}
	return s.clientFactory(credential), nil
}

type credentialContextKey struct{}

func withCredential(ctx context.Context, credential clicore.Credential) context.Context {
	return context.WithValue(ctx, credentialContextKey{}, credential)
}

func credentialFromContext(ctx context.Context) (clicore.Credential, bool) {
	credential, ok := ctx.Value(credentialContextKey{}).(clicore.Credential)
	return credential, ok
}

func (s *Server) previewFile(ctx context.Context, raw json.RawMessage) (any, error) {
	if _, err := s.client(ctx); err != nil {
		return nil, err
	}
	var args struct {
		Path string `json:"path"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	result, err := s.previewBuilder(args.Path)
	if err != nil {
		return nil, err
	}
	s.previews[result.CanonicalPath] = result
	_ = ctx
	return result, nil
}

func (s *Server) uploadFile(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	var args struct {
		Path              string `json:"path"`
		Confirm           bool   `json:"confirm"`
		OverrideSoftBlock bool   `json:"override_soft_block"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if !args.Confirm {
		return nil, errors.New("upload refused: share2us_upload_file requires explicit confirm: true after preview")
	}
	result, err := s.previewBuilder(args.Path)
	if err != nil {
		return nil, err
	}
	previous, ok := s.previews[result.CanonicalPath]
	if !ok || previous.SHA256 != result.SHA256 {
		return nil, errors.New("upload refused: path must first be preflighted by share2us_preview_file")
	}
	if result.Protection == preflight.ProtectionHard {
		return nil, errors.New("upload refused: hard-blocked secret or credential material detected")
	}
	if result.Protection == preflight.ProtectionSoft && !args.OverrideSoftBlock {
		return nil, errors.New("upload refused: soft-block findings require override_soft_block: true")
	}
	return uploadBytes(ctx, client, s.recipientBase, result.Filename, result.ContentType, result.ContentClass, result.RequestedExpiry, result.SHA256, result.SizeBytes, func() (io.ReadCloser, error) {
		return os.Open(result.CanonicalPath)
	})
}

func (s *Server) shareText(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	var args struct {
		Text      string `json:"text"`
		Name      string `json:"name"`
		ExpiresIn string `json:"expires_in"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Text == "" {
		return nil, errors.New("text is required")
	}
	// share_text bypassed preflight entirely; scan it too so an agent can't paste
	// a private key or provider token into `text` (AGENTS.md #7 — hard-block
	// high-confidence secrets on the agent path).
	if scan, err := clicore.ScanBytesForSecrets([]byte(args.Text), clicore.SecretScanOptions{}); err == nil {
		for _, f := range scan.Findings {
			if f.HighConfidence {
				return nil, fmt.Errorf("refused: the shared text contains a high-confidence secret (%s) and cannot be shared through MCP", f.RuleID)
			}
		}
	}
	name := strings.TrimSpace(args.Name)
	if name == "" {
		name = "share.txt"
	}
	expiresIn := strings.TrimSpace(args.ExpiresIn)
	if expiresIn == "" {
		expiresIn = "24h"
	}
	sum := sha256String(args.Text)
	return uploadBytes(ctx, client, s.recipientBase, name, "text/plain; charset=utf-8", "text", expiresIn, sum, uint64(len(args.Text)), func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(args.Text)), nil
	})
}

func (s *Server) listShares(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	return client.ListShares(ctx)
}

func (s *Server) getShare(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	var args struct {
		PublicID string `json:"public_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	shares, err := client.ListShares(ctx)
	if err != nil {
		return nil, err
	}
	for _, share := range shares.Shares {
		if share.PublicID == args.PublicID {
			return share, nil
		}
	}
	return nil, errors.New("share not found")
}

func (s *Server) revokeShare(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	var args struct {
		PublicID string `json:"public_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	return client.RevokeShare(ctx, args.PublicID)
}

func (s *Server) extendExpiry(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	var args struct {
		PublicID  string `json:"public_id"`
		ExpiresIn string `json:"expires_in"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	duration, err := clicore.ParseDuration(args.ExpiresIn)
	if err != nil {
		return nil, err
	}
	if duration <= 0 {
		return nil, errors.New("expires_in must be a positive duration")
	}
	return client.ExtendExpiry(ctx, args.PublicID, duration)
}

func (s *Server) getUsage(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	return client.Usage(ctx)
}

func (s *Server) getPlanLimits(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	usage, err := client.Usage(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"storage_quota_bytes":        usage.StorageQuotaBytes,
		"monthly_upload_limit_bytes": usage.MonthlyUploadLimitBytes,
		"max_active_shares":          usage.MaxActiveShares,
		"max_file_size_bytes":        usage.MaxFileSizeBytes,
		"max_downloads_per_share":    usage.MaxDownloadsPerShare,
		"default_expiry_hours":       usage.DefaultExpiryHours,
		"maximum_expiry_hours":       usage.MaximumExpiryHours,
		"allowed_content_classes":    usage.AllowedContentClasses,
		"password_protection":        usage.PasswordProtection,
		"one_time_download":          usage.OneTimeDownload,
	}, nil
}

func uploadBytes(ctx context.Context, client Client, recipientBase, name, contentType, contentClass, expiresIn, sum string, size uint64, open func() (io.ReadCloser, error)) (any, error) {
	apiExpiry, err := clicore.DurationForAPI(expiresIn)
	if err != nil {
		return nil, err
	}
	created, err := client.CreateUpload(ctx, clicore.UploadCreateRequest{
		FileName:     name,
		SizeBytes:    size,
		ContentType:  contentType,
		ContentClass: contentClass,
		ExpiresIn:    apiExpiry,
		SHA256:       sum,
		// Every upload through the MCP tools is an AI-agent upload; declare it so
		// the share records source_type='mcp' (AGENTS.md #7 — no silent agent uploads).
		Source: "mcp",
	})
	if err != nil {
		return nil, err
	}
	body, err := open()
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if err := client.PutUpload(ctx, created.Upload, body, int64(size)); err != nil {
		return nil, err
	}
	completed, err := client.CompleteUpload(ctx, created.UploadSessionID)
	if err != nil {
		return nil, err
	}
	publicID := completed.PublicID
	if publicID == "" {
		publicID = created.Share.PublicID
	}
	expiresAt := completed.ExpiresAt
	if expiresAt == "" {
		expiresAt = created.ExpiresAt
	}
	return map[string]any{
		"public_id":  publicID,
		"link":       recipientBase + "/" + publicID,
		"expires_at": expiresAt,
	}, nil
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])
}

func decodeArgs(raw json.RawMessage, out any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte(`{}`)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

func descriptor(name, description string, schema map[string]any) ToolDescriptor {
	return ToolDescriptor{Name: name, Description: description, InputSchema: schema}
}

func objectSchema(properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
}

func stringSchema() map[string]string { return map[string]string{"type": "string"} }
func boolSchema() map[string]string   { return map[string]string{"type": "boolean"} }

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func rpcOK(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func rpcErr(id json.RawMessage, code int, message string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

func toolResult(value any) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": mustJSON(value)}}}
}

func toolError(message string) map[string]any {
	return map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": message}}}
}

func mustJSON(value any) string {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(raw)
}
