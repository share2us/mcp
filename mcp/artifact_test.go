package mcp

import (
	"strings"
	"testing"
)

func TestPublishArtifactSendsAnArtifactUpload(t *testing.T) {
	client := &fakeClient{}
	server := testServer(client)
	out, err := server.publishArtifact(t.Context(), mustRaw(`{"html":"<p>hi</p>","name":"Mortgage calculator","private":true}`))
	if err != nil {
		t.Fatal(err)
	}
	got := client.lastCreate
	if got.ContentClass != "artifact" || got.ContentType != "text/html" || got.FileName != "Mortgage calculator.html" ||
		got.Visibility != "private" || got.Source != "mcp" || got.SizeBytes != uint64(len("<p>hi</p>")) || got.Encrypted {
		t.Fatalf("create request = %+v", got)
	}
	m := out.(map[string]any)
	if m["artifact"] != true || !strings.HasSuffix(m["link"].(string), "/pub-1") {
		t.Fatalf("result = %+v", m)
	}
}

func TestPublishArtifactDefaultsAndRefusals(t *testing.T) {
	client := &fakeClient{}
	server := testServer(client)
	if _, err := server.publishArtifact(t.Context(), mustRaw(`{"html":"<p>x</p>"}`)); err != nil {
		t.Fatal(err)
	}
	if client.lastCreate.FileName != "artifact.html" || client.lastCreate.Visibility != "" {
		t.Fatalf("defaults = %+v", client.lastCreate)
	}
	for body, want := range map[string]string{
		`{"html":"   "}`: "html is required",
		`{"html":"<script>var k='-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n-----END OPENSSH PRIVATE KEY-----\n'</script>"}`: "high-confidence secret",
	} {
		if _, err := server.publishArtifact(t.Context(), mustRaw(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", body, err, want)
		}
	}
}

// The description is what makes a model write artifacts that work in the sandbox.
func TestPublishArtifactIsListedWithItsSandboxRules(t *testing.T) {
	for _, d := range testServer(&fakeClient{}).Tools() {
		if d.Name == "share2us_publish_artifact" {
			for _, rule := range []string{"NO network", "localStorage", "self-contained"} {
				if !strings.Contains(d.Description, rule) {
					t.Fatalf("description lacks %q", rule)
				}
			}
			return
		}
	}
	t.Fatal("share2us_publish_artifact is not listed")
}
