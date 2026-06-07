package deps

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseInstallCommands(t *testing.T) {
	cases := []struct {
		cmd  string
		eco  string
		pkgs string
	}{
		{"npm install react-dropzone-truffle", "npm", "react-dropzone-truffle"},
		{"npm i lodash@4.17.4 express", "npm", "lodash,express"},
		{"yarn add @scope/pkg@1.2.3", "npm", "@scope/pkg"},
		{"pnpm add left-pad", "npm", "left-pad"},
		{"sudo pip install requests==2.0 flask", "PyPI", "requests,flask"},
		{"pip install -r requirements.txt", "PyPI", ""}, // manifest install → no named pkgs
		{"python3 -m pip install evilpkg", "PyPI", "evilpkg"},
		{"poetry add jinja2", "PyPI", "jinja2"},
		{"go get github.com/foo/bar@v1.2.3", "Go", "github.com/foo/bar"},
		{"cargo add serde", "crates.io", "serde"},
		{"gem install nokogiri", "RubyGems", "nokogiri"},
		{"cd app && npm install bad-pkg", "npm", "bad-pkg"},
		{"npm install", "", ""},      // bare → nothing named
		{"ls -la", "", ""},           // not an install
		{"npm run build", "", ""},    // not install verb
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			cmds := parseInstallCommands(tc.cmd)
			if tc.pkgs == "" {
				if len(cmds) != 0 {
					t.Fatalf("expected no install cmds, got %+v", cmds)
				}
				return
			}
			if len(cmds) == 0 {
				t.Fatalf("expected an install cmd, got none")
			}
			if cmds[0].ecosystem != tc.eco {
				t.Errorf("ecosystem = %q, want %q", cmds[0].ecosystem, tc.eco)
			}
			if got := strings.Join(cmds[0].packages, ","); got != tc.pkgs {
				t.Errorf("packages = %q, want %q", got, tc.pkgs)
			}
		})
	}
}

func TestIsInstallish(t *testing.T) {
	yes := []string{"npm install", "npm install foo", "pip install -r req.txt", "yarn add x", "cd a && pnpm i"}
	no := []string{"ls", "npm run test", "echo hi", "git commit"}
	for _, c := range yes {
		if !isInstallish(c) {
			t.Errorf("isInstallish(%q) = false, want true", c)
		}
	}
	for _, c := range no {
		if isInstallish(c) {
			t.Errorf("isInstallish(%q) = true, want false", c)
		}
	}
}

func TestGuardDeniesMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/malware-check" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok", "checked": 1, "malicious_count": 1,
			"results": []map[string]any{{
				"ecosystem": "npm", "package": "evilpkg", "malicious": true,
				"advisories": []map[string]any{{
					"id": "MAL-2026-1", "summary": "Malicious code in evilpkg",
					"refs": []map[string]any{{"url": "https://example/advisory", "type": "ADVISORY"}},
				}},
			}},
		})
	}))
	defer srv.Close()

	in := `{"tool_name":"Bash","tool_input":{"command":"npm install evilpkg"}}`
	var out bytes.Buffer
	if err := Guard(strings.NewReader(in), &out, NewClient(srv.URL)); err != nil {
		t.Fatalf("Guard: %v", err)
	}
	var dec struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &dec); err != nil {
		t.Fatalf("decode: %v (out=%q)", err, out.String())
	}
	if dec.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny", dec.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(dec.HookSpecificOutput.PermissionDecisionReason, "MAL-2026-1") ||
		!strings.Contains(dec.HookSpecificOutput.PermissionDecisionReason, "evilpkg") {
		t.Errorf("reason missing detail: %q", dec.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestGuardSilentOnClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "checked": 1, "malicious_count": 0, "results": []any{}})
	}))
	defer srv.Close()
	var out bytes.Buffer
	if err := Guard(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"npm install express"}}`), &out, NewClient(srv.URL)); err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected silent allow, got %q", out.String())
	}
}

func TestGuardFailOpenOnBadInput(t *testing.T) {
	var out bytes.Buffer
	// nil client would panic if it ever got called — proves we bail before the call.
	if err := Guard(strings.NewReader("not json"), &out, nil); err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output on bad input, got %q", out.String())
	}
}
