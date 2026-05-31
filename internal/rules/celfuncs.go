package rules

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// adapter converts native Go values (the shape terraform-json/encoding-json
// produce) into CEL values.
var adapter = types.DefaultTypeAdapter

// sensitivePorts are admin / database / cache ports that should never be open
// to the internet. A rule asks hits_sensitive_port(from, to) whether the
// inclusive [from,to] range covers any of these.
var sensitivePorts = []float64{
	22,    // SSH
	23,    // Telnet
	135,   // MSRPC
	445,   // SMB
	1433,  // MSSQL
	1521,  // Oracle
	3306,  // MySQL/MariaDB
	3389,  // RDP
	5432,  // PostgreSQL
	5439,  // Redshift
	6379,  // Redis
	9042,  // Cassandra
	9200,  // Elasticsearch
	11211, // Memcached
	27017, // MongoDB
}

// customFuncs returns the CEL function library bumper rules can call. These
// keep predicates short and correct, and parse_json unlocks the whole IAM
// family (policy documents are JSON strings inside the plan).
func customFuncs() []cel.EnvOption {
	return []cel.EnvOption{
		// parse_json(s) parses a JSON string into a dynamic value. On any error
		// (not a string, malformed JSON) it returns an empty object so callers
		// can guard with has(...) rather than crashing the evaluation.
		cel.Function("parse_json",
			cel.Overload("parse_json_string",
				[]*cel.Type{cel.StringType}, cel.DynType,
				cel.UnaryBinding(parseJSON))),

		// as_list(x) normalizes the IAM "string or array" idiom: a list stays a
		// list, null becomes [], and any scalar/object becomes a 1-element list.
		cel.Function("as_list",
			cel.Overload("as_list_dyn",
				[]*cel.Type{cel.DynType}, cel.ListType(cel.DynType),
				cel.UnaryBinding(asList))),

		// hits_sensitive_port(from, to) reports whether the inclusive port range
		// covers any sensitive admin/db/cache port.
		cel.Function("hits_sensitive_port",
			cel.Overload("hits_sensitive_port_double_double",
				[]*cel.Type{cel.DoubleType, cel.DoubleType}, cel.BoolType,
				cel.BinaryBinding(hitsSensitivePort))),

		// ports_hit_sensitive(list<string>) — GCP firewall `ports` are strings and may
		// be ranges ("8080-8090"). True if any entry covers a sensitive port.
		cel.Function("ports_hit_sensitive",
			cel.Overload("ports_hit_sensitive_list",
				[]*cel.Type{cel.ListType(cel.DynType)}, cel.BoolType,
				cel.UnaryBinding(portsHitSensitive))),
	}
}

func parseJSON(v ref.Val) ref.Val {
	s, ok := v.Value().(string)
	if !ok {
		return adapter.NativeToValue(map[string]interface{}{})
	}
	var out interface{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return adapter.NativeToValue(map[string]interface{}{})
	}
	return adapter.NativeToValue(out)
}

func asList(v ref.Val) ref.Val {
	switch v.Type().TypeName() {
	case "list":
		return v
	case "null_type":
		return adapter.NativeToValue([]interface{}{})
	default:
		return types.NewDynamicList(adapter, []ref.Val{v})
	}
}

func hitsSensitivePort(a, b ref.Val) ref.Val {
	from, ok1 := a.Value().(float64)
	to, ok2 := b.Value().(float64)
	if !ok1 || !ok2 {
		return types.False
	}
	if to < from {
		from, to = to, from
	}
	for _, p := range sensitivePorts {
		if from <= p && p <= to {
			return types.True
		}
	}
	return types.False
}

func portsHitSensitive(v ref.Val) ref.Val {
	list, ok := v.(traits.Lister)
	if !ok {
		return types.False
	}
	for it := list.Iterator(); it.HasNext() == types.True; {
		s, ok := it.Next().Value().(string)
		if !ok {
			continue
		}
		from, to := s, s
		if i := strings.IndexByte(s, '-'); i >= 0 {
			from, to = s[:i], s[i+1:]
		}
		lo, e1 := strconv.ParseFloat(from, 64)
		hi, e2 := strconv.ParseFloat(to, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		for _, p := range sensitivePorts {
			if lo <= p && p <= hi {
				return types.True
			}
		}
	}
	return types.False
}
