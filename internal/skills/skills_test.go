package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestContentMatchesCatalog verifies every catalogued skill embeds a SKILL.md
// whose frontmatter `name:` matches its folder/Name — the invariant the npx and
// marketplace channels also rely on.
func TestContentMatchesCatalog(t *testing.T) {
	for _, s := range All {
		raw, err := s.raw()
		if err != nil {
			t.Fatalf("%s: no embedded SKILL.md: %v", s.Name, err)
		}
		if !strings.HasPrefix(raw, "---\n") {
			t.Errorf("%s: missing YAML frontmatter", s.Name)
		}
		want := "name: " + s.Name
		if !strings.Contains(raw, want) {
			t.Errorf("%s: frontmatter name does not match folder (want %q)", s.Name, want)
		}
		if !strings.Contains(raw, "description:") {
			t.Errorf("%s: frontmatter missing description", s.Name)
		}
		// The hybrid body must point back at the CLI for version-matched content.
		if !strings.Contains(raw, "bumper skills get "+s.Short) {
			t.Errorf("%s: body missing `bumper skills get %s` pointer", s.Name, s.Short)
		}
	}
}

func TestFind(t *testing.T) {
	for _, s := range All {
		if got, ok := Find(s.Short); !ok || got.Name != s.Name {
			t.Errorf("Find(%q) = %v, %v", s.Short, got, ok)
		}
		if got, ok := Find(strings.ToUpper(s.Name)); !ok || got.Name != s.Name {
			t.Errorf("Find(%q) case-insensitive failed", s.Name)
		}
	}
	if _, ok := Find("nope"); ok {
		t.Error("Find(nope) should fail")
	}
}

func TestGetStripsFrontmatter(t *testing.T) {
	body, err := Get("plan-gate")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(body, "---") {
		t.Error("Get should strip the YAML frontmatter")
	}
	if !strings.HasPrefix(body, "# ") {
		t.Errorf("Get body should start at the heading, got: %.20q", body)
	}
	if _, err := Get("bogus"); err == nil {
		t.Error("Get(bogus) should error")
	}
}

func TestInstallIdempotent(t *testing.T) {
	dir := t.TempDir()

	// First install: every skill is created.
	results, err := Install(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(All) {
		t.Fatalf("got %d results, want %d", len(results), len(All))
	}
	for _, r := range results {
		if !r.Created {
			t.Errorf("%s: want Created on first install", r.Skill.Name)
		}
		if _, err := os.Stat(r.Path); err != nil {
			t.Errorf("%s: file not written: %v", r.Skill.Name, err)
		}
		if filepath.Base(r.Path) != "SKILL.md" {
			t.Errorf("%s: want SKILL.md, got %s", r.Skill.Name, r.Path)
		}
	}

	// Second install: nothing changes.
	results, err = Install(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Created || r.Updated {
			t.Errorf("%s: want unchanged on re-install, got created=%v updated=%v", r.Skill.Name, r.Created, r.Updated)
		}
	}

	// Mutated file is restored to Updated.
	target := filepath.Join(dir, All[0].Name, "SKILL.md")
	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err = Install(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Updated {
		t.Errorf("%s: want Updated after mutation", results[0].Skill.Name)
	}
}

// TestInstalledBytesMatchEmbedded guards the cross-channel invariant: what
// `install` writes is byte-identical to the embedded source (and thus to the
// files the npx/marketplace channels publish).
func TestInstalledBytesMatchEmbedded(t *testing.T) {
	dir := t.TempDir()
	if _, err := Install(dir); err != nil {
		t.Fatal(err)
	}
	for _, s := range All {
		want, _ := s.raw()
		got, err := os.ReadFile(filepath.Join(dir, s.Name, "SKILL.md"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s: installed bytes differ from embedded source", s.Name)
		}
	}
}
