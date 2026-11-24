package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	clicore "github.com/share2us/cli-core"
)

// artifactToolDescription is written for the model that will call the tool: an artifact
// that assumes network access or storage silently breaks, so the limits come first.
const artifactToolDescription = "Publish a self-contained HTML page as an interactive artifact (a mini app, chart, " +
	"calculator, game or visualisation) and get a share link. Whoever opens the link can RUN it: it executes " +
	"in an isolated sandbox on share2us.site, below a banner saying it came from this account. " +
	"Build it to work under these sandbox rules: ONE self-contained HTML file with inline <script> and <style>; " +
	"NO network (fetch/XHR/WebSocket and external scripts, stylesheets, fonts or images all fail, so inline " +
	"everything and use data: URIs for images); NO forms that submit, NO cookies, localStorage or " +
	"sessionStorage (keep state in JS variables), NO popups, alerts or new windows, NO camera, microphone, " +
	"clipboard or geolocation. Canvas, SVG, CSS animation and plain DOM all work. The page is malware-scanned " +
	"first, so the link opens a few seconds after publishing. Free plans allow pages up to 5 MB. " +
	"Args: html (the full page, required), name (file name, default artifact.html), expires_in (optional, " +
	"default 24h), private (optional, true = only this account can open it)."

func (s *Server) publishArtifact(ctx context.Context, raw json.RawMessage) (any, error) {
	client, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	var args struct {
		HTML      string `json:"html"`
		Name      string `json:"name"`
		ExpiresIn string `json:"expires_in"`
		Private   bool   `json:"private"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(args.HTML) == "" {
		return nil, errors.New("html is required")
	}
	if !utf8.ValidString(args.HTML) {
		return nil, errors.New("html must be UTF-8 text")
	}
	// Same hard block as share_text: an agent must not publish a credential it was
	// handed, least of all inside a page that runs for strangers (AGENTS.md #7).
	if scan, err := clicore.ScanBytesForSecrets([]byte(args.HTML), clicore.SecretScanOptions{}); err == nil {
		for _, f := range scan.Findings {
			if f.HighConfidence {
				return nil, fmt.Errorf("refused: the page contains a high-confidence secret (%s) and cannot be published through MCP", f.RuleID)
			}
		}
	}
	name := artifactFileName(args.Name)
	expiresIn := strings.TrimSpace(args.ExpiresIn)
	if expiresIn == "" {
		expiresIn = "24h"
	}
	apiExpiry, err := clicore.DurationForAPI(expiresIn)
	if err != nil {
		return nil, err
	}
	req := clicore.UploadCreateRequest{
		FileName:     name,
		SizeBytes:    uint64(len(args.HTML)),
		ContentType:  "text/html",
		ContentClass: "artifact",
		ExpiresIn:    apiExpiry,
		SHA256:       sha256String(args.HTML),
		Source:       "mcp",
	}
	if args.Private {
		req.Visibility = "private"
	}
	created, err := client.CreateUpload(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := client.PutUpload(ctx, created.Upload, io.NopCloser(strings.NewReader(args.HTML)), int64(len(args.HTML))); err != nil {
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
	note := "Interactive artifact published. Whoever opens the link can run it in an isolated sandbox."
	if completed.Status == "scanning" {
		note += " It is being malware-scanned; the link opens once the scan passes, usually within seconds."
	}
	return map[string]any{
		"public_id":  publicID,
		"link":       s.recipientBase + "/" + publicID,
		"expires_at": expiresAt,
		"status":     completed.Status,
		"artifact":   true,
		"note":       note,
	}, nil
}

// artifactFileName keeps the name an .html file: the server refuses an artifact with
// any other extension, and a model may well pass "Mortgage calculator".
func artifactFileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "artifact.html"
	}
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm") {
		return name
	}
	return name + ".html"
}
