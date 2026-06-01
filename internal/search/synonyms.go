package search

import "strings"

// synonymGroups expand a query across bumper's closed, known cloud-security
// vocabulary — the cheap, deterministic stand-in for semantic search on the
// local binary. Each group is a set of mutually-substitutable tokens; a query
// term matching any member also searches the rest (at reduced weight). Tokens
// are single words because the tokenizer splits on non-alphanumerics, so e.g.
// "aws_security_group" indexes as security/group, and "firewall" reaches it via
// the {firewall, security, group, sg, nsg} group.
var synonymGroups = [][]string{
	{"database", "db", "rds", "sql", "mysql", "postgres", "postgresql", "aurora", "mariadb", "cloudsql", "cosmosdb", "spanner"},
	{"storage", "s3", "bucket", "blob", "gcs"},
	{"public", "internet", "exposed", "anonymous", "allusers", "everyone"},
	{"ssh", "22"},
	{"rdp", "3389"},
	{"encryption", "encrypted", "unencrypted", "encrypt", "kms", "cmk", "cmek", "sse", "tde"},
	{"firewall", "security", "group", "sg", "nsg", "ingress", "egress"},
	{"kubernetes", "k8s", "eks", "gke", "aks", "cluster", "container"},
	{"serverless", "lambda", "function", "cloudfunction", "functions"},
	{"iam", "role", "policy", "permission", "privilege", "wildcard", "admin"},
	{"tls", "ssl", "https", "certificate", "cert"},
	{"logging", "audit", "cloudtrail", "logs", "log", "flow"},
	{"network", "vpc", "subnet", "networking", "subnetwork"},
	{"snapshot", "backup", "ami", "image"},
	{"secret", "password", "credential", "key", "plaintext"},
	{"registry", "ecr", "acr", "gcr", "artifact"},
	{"queue", "sqs", "sns", "pubsub", "topic", "messaging"},
	{"cache", "redis", "elasticache", "memcached", "memorystore"},
	{"rotation", "rotate", "expiry", "expiration"},
	{"deletion", "destroy", "delete", "replace"},
}

// synonyms maps each token to the union of every group it appears in (excluding
// itself). Built once at init.
var synonyms = buildSynonyms()

func buildSynonyms() map[string][]string {
	m := map[string]map[string]bool{}
	for _, g := range synonymGroups {
		for _, a := range g {
			if m[a] == nil {
				m[a] = map[string]bool{}
			}
			for _, b := range g {
				if b != a {
					m[a][b] = true
				}
			}
		}
	}
	out := make(map[string][]string, len(m))
	for term, set := range m {
		for s := range set {
			out[term] = append(out[term], s)
		}
	}
	return out
}

func synonymsOf(term string) []string {
	return synonyms[strings.ToLower(term)]
}
