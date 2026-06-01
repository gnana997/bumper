package search_test

import (
	"testing"

	"github.com/gnana997/bumper/internal/catalog"
	"github.com/gnana997/bumper/internal/rules"
	"github.com/gnana997/bumper/internal/search"
)

func index(t *testing.T) *search.Index {
	t.Helper()
	set, err := rules.Load("")
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	return search.New(set, cat)
}

func enforcedIDs(hits []search.Hit) map[string]bool {
	m := map[string]bool{}
	for _, h := range hits {
		if h.Doc.Enforced {
			m[h.Doc.Rule.ID] = true
		}
	}
	return m
}

// TestKeywordPrecision: the topicality gate keeps "s3 public" from returning
// every public-anything rule — the precision bug this design fixes.
func TestKeywordPrecision(t *testing.T) {
	hits := index(t).Search(search.Query{Text: "s3 public", Limit: 60})
	ids := enforcedIDs(hits)
	for _, want := range []string{"AWS_S3_BUCKET_PUBLIC_ACL", "AWS_S3_ACL_PUBLIC", "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK"} {
		if !ids[want] {
			t.Errorf("expected %s for \"s3 public\"", want)
		}
	}
	for _, bad := range []string{"AWS_SG_PUBLIC_INGRESS", "GCP_IAM_PUBLIC_MEMBER", "AWS_EKS_PUBLIC_ENDPOINT_OPEN"} {
		if ids[bad] {
			t.Errorf("%s matched \"public\" but not \"s3\" — should be gated out", bad)
		}
	}
}

// TestSynonymRecall: "database" should reach RDS/SQL rules via the synonym map,
// even though those rules say "RDS"/"SQL", not "database".
func TestSynonymRecall(t *testing.T) {
	hits := index(t).Search(search.Query{Text: "database", Limit: 60})
	ids := enforcedIDs(hits)
	found := ids["AWS_RDS_PUBLICLY_ACCESSIBLE"] || ids["AWS_RDS_STORAGE_UNENCRYPTED"] || ids["GCP_SQL_PUBLIC_ACCESS"]
	if !found {
		t.Errorf("synonym recall failed: \"database\" surfaced no RDS/SQL rule; got %v", ids)
	}
}

// TestResourceFilter returns rules for a resource type, including the type-less
// destruction rule matched via the predicate text.
func TestResourceFilter(t *testing.T) {
	hits := index(t).Search(search.Query{Resource: "google_sql_database_instance", Limit: 60})
	ids := enforcedIDs(hits)
	for _, want := range []string{"GCP_SQL_PUBLIC_ACCESS", "GCP_SQL_NO_SSL", "GCP_STATEFUL_RESOURCE_DESTROY"} {
		if !ids[want] {
			t.Errorf("expected %s for resource google_sql_database_instance; got %v", want, ids)
		}
	}
}

// TestFilters constrain by provider + severity across both corpora.
func TestFilters(t *testing.T) {
	hits := index(t).Search(search.Query{Provider: "azure", Severity: "high", Limit: 200})
	if len(hits) == 0 {
		t.Fatal("expected azure/high hits")
	}
	for _, h := range hits {
		var prov, sev string
		if h.Doc.Enforced {
			prov, sev = h.Doc.Rule.Provider, h.Doc.Rule.Severity
		} else {
			prov, sev = h.Doc.Entry.Provider, h.Doc.Entry.Severity
		}
		if prov != "azure" || sev != "high" {
			t.Errorf("filter leak: provider=%s severity=%s", prov, sev)
		}
	}
}

// TestCorpusMix: a broad query draws from BOTH the enforced rules and the
// advisory catalog; Split partitions them.
func TestCorpusMix(t *testing.T) {
	hits := index(t).Search(search.Query{Text: "storage", Limit: 60})
	enf, adv := search.Split(hits)
	if len(enf) == 0 || len(adv) == 0 {
		t.Fatalf("expected both corpora; enforced=%d advisory=%d", len(enf), len(adv))
	}
	for _, h := range adv {
		if h.Doc.Entry == nil || h.Doc.Enforced {
			t.Errorf("advisory hit malformed: %+v", h.Doc)
		}
	}
}

// TestNoMatch: a query hitting nothing returns empty, not everything.
func TestNoMatch(t *testing.T) {
	if hits := index(t).Search(search.Query{Text: "zzzznotathing"}); len(hits) != 0 {
		t.Errorf("expected no hits, got %d", len(hits))
	}
}
