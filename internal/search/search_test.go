package search_test

import (
	"testing"

	"github.com/gnana997/bumper/internal/rules"
	"github.com/gnana997/bumper/internal/search"
)

func load(t *testing.T) *rules.Set {
	t.Helper()
	set, err := rules.Load("")
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	return set
}

func ids(res []search.Result) map[string]int {
	m := make(map[string]int, len(res))
	for i, r := range res {
		m[r.Rule.ID] = i // rank position
	}
	return m
}

// TestKeywordRanks a free-text query surfaces the on-topic rules, ranked.
func TestKeywordRanks(t *testing.T) {
	res := search.Rules(load(t), search.Query{Text: "s3 public"})
	if len(res) == 0 {
		t.Fatal("expected hits for \"s3 public\"")
	}
	got := ids(res)
	for _, id := range []string{"AWS_S3_BUCKET_PUBLIC_ACL", "AWS_S3_ACL_PUBLIC", "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK"} {
		if _, ok := got[id]; !ok {
			t.Errorf("expected %s in results for \"s3 public\"", id)
		}
	}
	// Every returned rule must carry a positive score and be flagged enforced.
	for _, r := range res {
		if r.Score <= 0 {
			t.Errorf("%s returned with non-positive score %d", r.Rule.ID, r.Score)
		}
		if !r.Enforced {
			t.Errorf("%s should be Enforced=true", r.Rule.ID)
		}
	}
}

// TestResourceFilter returns every rule for a resource type — including the
// type-less destruction family matched via the CEL predicate text.
func TestResourceFilter(t *testing.T) {
	res := search.Rules(load(t), search.Query{Resource: "google_sql_database_instance"})
	got := ids(res)
	for _, id := range []string{
		"GCP_SQL_PUBLIC_ACCESS", "GCP_SQL_NO_SSL",
		"GCP_STATEFUL_RESOURCE_DESTROY", // type-less, matched via When
	} {
		if _, ok := got[id]; !ok {
			t.Errorf("expected %s for resource google_sql_database_instance; got %v", id, got)
		}
	}
	// A different resource's rule must not leak in.
	if _, ok := got["AWS_S3_BUCKET_PUBLIC_ACL"]; ok {
		t.Error("aws rule leaked into a google_sql resource search")
	}
}

// TestProviderAndSeverityFilters constrain the corpus.
func TestProviderAndSeverityFilters(t *testing.T) {
	res := search.Rules(load(t), search.Query{Provider: "azure", Severity: "high"})
	if len(res) == 0 {
		t.Fatal("expected azure high-severity rules")
	}
	for _, r := range res {
		if r.Rule.Provider != "azure" {
			t.Errorf("%s has provider %q, want azure", r.Rule.ID, r.Rule.Provider)
		}
		if r.Rule.Severity != "high" {
			t.Errorf("%s has severity %q, want high", r.Rule.ID, r.Rule.Severity)
		}
	}
}

// TestNoMatch a text query that hits nothing returns empty, not everything.
func TestNoMatch(t *testing.T) {
	res := search.Rules(load(t), search.Query{Text: "zzzznotathing"})
	if len(res) != 0 {
		t.Errorf("expected no hits, got %d", len(res))
	}
}

// TestLimit caps the result count.
func TestLimit(t *testing.T) {
	res := search.Rules(load(t), search.Query{Provider: "aws", Limit: 3})
	if len(res) != 3 {
		t.Errorf("expected 3 results with Limit=3, got %d", len(res))
	}
}
