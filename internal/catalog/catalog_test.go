package catalog_test

import (
	"testing"

	"github.com/gnana997/bumper/internal/catalog"
)

func TestLoad(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, src := range catalog.Sources {
		if c.Count(src) == 0 {
			t.Errorf("source %q is empty", src)
		}
	}
	if c.Total() < 2000 {
		t.Errorf("expected the full corpus, got %d total", c.Total())
	}
}

func TestEntries(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	entries := c.Entries()
	if len(entries) != c.Total() {
		t.Errorf("Entries() returned %d, Total() is %d", len(entries), c.Total())
	}
	// Spot-check the envelope is populated.
	for _, e := range entries {
		if e.Source == "" || e.SourceID == "" || e.Title == "" {
			t.Errorf("malformed entry: %+v", e)
			break
		}
	}
}
