// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	clicore "github.com/share2us/cli-core"
)

// This file exposes a small programmatic surface so an alternate transport (the
// hosted Streamable-HTTP server in share2us-mcp-remote, built on the official MCP
// Go SDK) can reuse these tool definitions and handlers verbatim instead of
// duplicating the share logic. The stdio (Serve) and one-shot HTTP (ServeHTTP)
// transports keep working unchanged.

// Tools returns the enabled tools' descriptors in stable registration order, for a
// transport that needs to answer tools/list itself.
func (s *Server) Tools() []ToolDescriptor {
	out := make([]ToolDescriptor, 0, len(toolOrder))
	for _, name := range toolOrder {
		if tool, ok := s.tools[name]; ok {
			out = append(out, tool.Descriptor)
		}
	}
	return out
}

// CallTool invokes a registered tool by name with raw JSON arguments and returns the
// tool's result value (or an error). The caller MUST place the Share2Us credential in
// ctx with WithCredential first; tool handlers read it to call share2us-api.
func (s *Server) CallTool(ctx context.Context, name string, args json.RawMessage) (any, error) {
	tool, ok := s.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	return tool.Handler(ctx, args)
}

// WithCredential returns ctx carrying the Share2Us credential used by tool handlers.
// The hosted transport resolves the request bearer to a credential and sets it here
// before each CallTool.
func WithCredential(ctx context.Context, credential clicore.Credential) context.Context {
	return withCredential(ctx, credential)
}
