// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package preflight

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Fake tokens are assembled at runtime so no literal token-shaped string sits in
// the repo for secret scanners or push protection to flag.
func fakePAT() string {
	return "s2u_" + "pat_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1" // 27-char body
}

func fakeSession() string {
	return "s2s" + "_" + "Zy9xWv8uTs7rQp6oNm5lKj4iHg3fEd2cBa1-_Xy0Wv9" // 43-char body
}

func TestShare2UsTokenFormatsMatchTheMinter(t *testing.T) {
	// Body lengths mirror the server: base64.RawURLEncoding of 20 / 32 bytes.
	if got := len(fakePAT()) - len("s2u_pat_"); got != 27 {
		t.Fatalf("fake PAT body = %d chars, want 27", got)
	}
	if got := len(fakeSession()) - len("s2s_"); got != 43 {
		t.Fatalf("fake session body = %d chars, want 43", got)
	}
}

func TestShare2UsTokenRules(t *testing.T) {
	positives := map[string]string{
		"bare PAT":                fakePAT(),
		"PAT in env assignment":   "SHARE2US_API_TOKEN=" + fakePAT() + "\n",
		"PAT in JSON":             `{"token":"` + fakePAT() + `"}`,
		"PAT in bearer header":    "Authorization: Bearer " + fakePAT(),
		"PAT glued to identifier": "export MY_" + fakePAT(),
		"bare session token":      fakeSession(),
		"session in credentials":  `{"api_base":"https://example.invalid","token":"` + fakeSession() + `"}`,
		"session on later line":   "line one\nline two\n" + fakeSession(),
		"session in binary blob":  "\x00\x01\xff" + fakeSession() + "\x00",
	}
	for name, body := range positives {
		t.Run("hit/"+name, func(t *testing.T) {
			f := share2usTokenFindings([]byte(body))
			if len(f) == 0 || f[0].Severity != "hard" {
				t.Fatalf("findings = %+v, want a hard finding", f)
			}
			if HighConfidenceSecret([]byte(body)) == "" {
				t.Fatal("HighConfidenceSecret() = \"\", want a rule id")
			}
		})
	}

	pat := fakePAT()
	sess := fakeSession()
	negatives := map[string]string{
		"prefix alone":              "s2u_" + "pat_",
		"short PAT body":            pat[:len(pat)-1],
		"short session body":        sess[:len(sess)-1],
		"PAT broken by a space":     pat[:20] + " " + pat[20:],
		"PAT body bad charset":      "s2u_" + "pat_" + "Ab3dEf6hIj9k.m2nOp5qRs8tUv1",
		"snake case identifier":     "s2s" + "_connection_pool_manager_factory_builder_impl_v",
		"upper case constant":       "s2s" + "_CONNECTION_POOL_MANAGER_FACTORY_BUILDER_IMPL_V",
		"lower case PAT-ish name":   "s2u_" + "pat_handler_registration_table_x",
		"doc mention of the prefix": "Personal access tokens start with s2u_" + "pat_ and are shown once.",
		"other s2 prefixes":         "s2u_unlock cookie and s2u_0123456789abcdef boundary",
		"ordinary prose":            "the s2s link was fast; ask s2u about it",
	}
	for name, body := range negatives {
		t.Run("miss/"+name, func(t *testing.T) {
			if f := share2usTokenFindings([]byte(body)); len(f) != 0 {
				t.Fatalf("findings = %+v, want none", f)
			}
		})
	}
}

func TestHighConfidenceSecretCleanAndGitleaks(t *testing.T) {
	if rule := HighConfidenceSecret([]byte("hello, nothing secret here")); rule != "" {
		t.Fatalf("clean text rule = %q", rule)
	}
	// Existing gitleaks/supplemental hard blocks still apply through the helper.
	if rule := HighConfidenceSecret([]byte("-----BEGIN PRIVATE KEY-----\nabc\n")); rule == "" {
		t.Fatal("private key header not reported")
	}
}

// A file containing a Share2Us token is HARD-blocked by Build, whatever its name.
func TestBuildHardBlocksShare2UsTokensInContent(t *testing.T) {
	for name, body := range map[string]string{
		"notes.txt":  "token: " + fakePAT() + "\n",
		"dump.json":  `{"token":"` + fakeSession() + `"}`,
		"blob.bin":   "\x00\x00" + fakeSession(),
		"script.sh":  "curl -H 'Authorization: Bearer " + fakePAT() + "' https://example.invalid\n",
		"backup.cfg": "a=1\nb=2\ntoken=" + fakeSession() + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := Build(path)
			if err != nil {
				t.Fatal(err)
			}
			if res.Protection != ProtectionHard || res.SecretScan.Status != SecretStatusBlock {
				t.Fatalf("protection/status = %s/%s, findings %+v", res.Protection, res.SecretScan.Status, res.SecretScan.Findings)
			}
		})
	}
}

// isolateConfig points every config-dir source at a temp dir and returns the
// share2us config dir that os.UserConfigDir resolves to on this OS.
func isolateConfig(t *testing.T) (home, configDir string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	t.Setenv("APPDATA", filepath.Join(home, "appdata"))
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	configDir = filepath.Join(base, "share2us")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return home, configDir
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireHard(t *testing.T, path string) {
	t.Helper()
	res, err := Build(path)
	if err != nil {
		t.Fatalf("Build(%q) error = %v", path, err)
	}
	if res.Protection != ProtectionHard {
		t.Fatalf("Build(%q) protection = %s, findings %+v; want hard", path, res.Protection, res.SecretScan.Findings)
	}
	for _, f := range res.SecretScan.Findings {
		if f.Kind == "prohibited_name" && f.Severity == "hard" && strings.Contains(f.Message, "Share2Us CLI credential") {
			return
		}
	}
	t.Fatalf("Build(%q) has no Share2Us credential-path finding: %+v", path, res.SecretScan.Findings)
}

// The credential file is blocked by PATH, even with content the token rules
// would not catch (e.g. an empty token field).
func TestBuildHardBlocksShare2UsCredentialFiles(t *testing.T) {
	_, dir := isolateConfig(t)
	for _, name := range share2usSecretFiles {
		path := filepath.Join(dir, name)
		writeFile(t, path, `{"token":""}`)
		t.Run(name, func(t *testing.T) { requireHard(t, path) })
	}
}

func TestBuildHardBlocksCredentialViaAliases(t *testing.T) {
	home, dir := isolateConfig(t)
	cred := filepath.Join(dir, "credentials.json")
	writeFile(t, cred, `{"token":""}`)

	t.Run("relative path with dot-dot", func(t *testing.T) {
		t.Chdir(dir)
		requireHard(t, filepath.Join("..", "share2us", "credentials.json"))
	})
	t.Run("plain relative path", func(t *testing.T) {
		t.Chdir(filepath.Dir(dir))
		requireHard(t, filepath.Join("share2us", "credentials.json"))
	})
	t.Run("tilde path", func(t *testing.T) {
		rel, err := filepath.Rel(home, cred)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Skip("config dir is not under HOME on this OS")
		}
		requireHard(t, "~/"+filepath.ToSlash(rel))
	})
	t.Run("symlink to the file", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "innocent.txt")
		if err := os.Symlink(cred, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		requireHard(t, link)
	})
	t.Run("symlinked directory", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "cfg")
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		requireHard(t, filepath.Join(link, "credentials.json"))
	})
	t.Run("hard link elsewhere", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "notes.txt")
		if err := os.Link(cred, link); err != nil {
			t.Skipf("hard link unsupported: %v", err)
		}
		requireHard(t, link)
	})
}

// cli-core still reads the pre-2026-07 location (XDG_CONFIG_HOME, else
// ~/.config, which on Windows is %USERPROFILE%\.config) as a fallback.
func TestBuildHardBlocksLegacyCredentialLocations(t *testing.T) {
	home, _ := isolateConfig(t)
	for _, path := range []string{
		filepath.Join(home, "xdg", "share2us", "credentials.json"),
		filepath.Join(home, ".config", "share2us", "credentials.json"),
		filepath.Join(home, "Library", "Application Support", "share2us", "credentials.json"),
		filepath.Join(home, "AppData", "Roaming", "share2us", "credentials.json"),
		filepath.Join(home, "appdata", "share2us", "credentials.json"),
	} {
		writeFile(t, path, `{"token":""}`)
		t.Run(path, func(t *testing.T) { requireHard(t, path) })
	}
}

// A copied or relocated share2us config dir (backup, test-isolated XDG dir) is
// still the CLI's credential file.
func TestBuildHardBlocksCopiedShare2UsConfigDir(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "backup", "Share2Us", "credentials.json")
	writeFile(t, path, `{"token":""}`)
	requireHard(t, path)
}

// Everything else keeps its old behaviour: an unrelated credentials.json is still
// only a SOFT block, and other files in the share2us config dir are not blocked
// by path.
func TestUnrelatedCredentialFilesStaySoft(t *testing.T) {
	_, dir := isolateConfig(t)
	other := filepath.Join(t.TempDir(), "gcloud", "credentials.json")
	writeFile(t, other, `{"type":"authorized_user"}`)
	res, err := Build(other)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protection != ProtectionSoft {
		t.Fatalf("unrelated credentials.json protection = %s, want soft", res.Protection)
	}

	cfg := filepath.Join(dir, "config.json")
	writeFile(t, cfg, `{"defaults":{}}`)
	res, err = Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protection != ProtectionNone {
		t.Fatalf("share2us config.json protection = %s, want none", res.Protection)
	}
}

// The pure path matcher must treat Windows-style paths case-insensitively and
// accept either separator, whatever OS the tests run on.
func TestIsShare2UsSecretPathWindowsStyle(t *testing.T) {
	protected := []string{
		`C:\Users\alice\AppData\Roaming\share2us\credentials.json`,
		`C:\Users\alice\.config\share2us\credentials.json`,
	}
	hits := []string{
		`C:\Users\alice\AppData\Roaming\share2us\credentials.json`,
		`c:\users\ALICE\appdata\roaming\Share2Us\Credentials.JSON`,
		`C:/Users/alice/AppData/Roaming/share2us/credentials.json`,
		`C:\Users\alice\.config\share2us\credentials.json`,
		`C:\USERS\ALICE\.CONFIG\SHARE2US\CREDENTIALS.JSON`,
		`D:\backups\share2us\lan_identity.json`,
		`D:\backups\SHARE2US\Pending_Reseal.json`,
		`D:\backups\share2us\daemon.token`,
		`/home/bob/.config/share2us/credentials.json`,
		`/Users/bob/Library/Application Support/share2us/credentials.json`,
	}
	for _, p := range hits {
		if !isShare2UsSecretPath(p, protected) {
			t.Errorf("isShare2UsSecretPath(%q) = false, want true", p)
		}
	}
	misses := []string{
		`C:\Users\alice\AppData\Roaming\gcloud\credentials.json`,
		`C:\Users\alice\AppData\Roaming\share2us\config.json`,
		`C:\Users\alice\AppData\Roaming\share2us\agents\bindings.json`,
		`C:\Users\alice\share2us-notes\credentials.json`,
		`credentials.json`,
		`/home/bob/projects/share2us/README.md`,
	}
	for _, p := range misses {
		if isShare2UsSecretPath(p, protected) {
			t.Errorf("isShare2UsSecretPath(%q) = true, want false", p)
		}
	}
}

func TestProtectedPathsCoverEveryPlatformLocation(t *testing.T) {
	home, _ := isolateConfig(t)
	paths := protectedCredentialPaths()
	want := []string{
		filepath.Join(home, "xdg", "share2us", "credentials.json"),
		filepath.Join(home, ".config", "share2us", "credentials.json"),
		filepath.Join(home, "appdata", "share2us", "credentials.json"),
	}
	if runtime.GOOS == "darwin" {
		want = append(want, filepath.Join(home, "Library", "Application Support", "share2us", "credentials.json"))
	}
	for _, w := range want {
		found := false
		for _, p := range paths {
			if normalizePath(p) == normalizePath(w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("protected paths missing %q", w)
		}
	}
}
