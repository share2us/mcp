// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	clicore "github.com/share2us/cli-core"
)

func TestServeHTTP(t *testing.T) {
	var gotCredential clicore.Credential
	client := &fakeClient{}
	server := NewServer(
		WithCredentialLoader(func() (clicore.Credential, error) {
			return clicore.Credential{}, errors.New("stdio credential should not be used")
		}),
		WithHTTPCredentialResolver(func(*http.Request) (clicore.Credential, error) {
			return clicore.Credential{APIBase: "https://api.example.test", Token: "s2s_http"}, nil
		}),
		WithClientFactory(func(credential clicore.Credential) Client {
			gotCredential = credential
			return client
		}),
	)

	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "initialize",
			body: `{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
			want: `"serverInfo"`,
		},
		{
			name: "tools list",
			body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			want: `"share2us_list_shares"`,
		},
		{
			name: "tools call",
			body: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"share2us_list_shares","arguments":{}}}`,
			want: `pub-1`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tt.body)))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tt.want) {
				t.Fatalf("body missing %q:\n%s", tt.want, response.Body.String())
			}
		})
	}

	if gotCredential.Token != "s2s_http" || gotCredential.APIBase != "https://api.example.test" {
		t.Fatalf("credential = %+v", gotCredential)
	}
}

func TestServeHTTPResolverError(t *testing.T) {
	server := NewServer(
		WithHTTPCredentialResolver(func(*http.Request) (clicore.Credential, error) {
			return clicore.Credential{}, errors.New("missing bearer")
		}),
		WithClientFactory(func(clicore.Credential) Client { return &fakeClient{} }),
	)

	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var decoded rpcResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded.Error == nil || decoded.Error.Code != -32001 {
		t.Fatalf("error = %+v", decoded.Error)
	}
}
