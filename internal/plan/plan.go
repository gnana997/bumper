// Package plan normalizes `terraform show -json` output into a shape that is
// convenient for rule evaluation. It flattens terraform-json's representation
// into before/after maps plus a normalized action list, so a CEL rule can read
// either the planned end-state (after) or the transition (actions) uniformly.
package plan

import (
	"encoding/json"
	"fmt"

	tfjson "github.com/hashicorp/terraform-json"
)

// ResourceChange is a normalized view of a single planned change.
type ResourceChange struct {
	Address string
	Type    string
	Name    string
	// Actions is the normalized change set: one or more of
	// create|read|update|delete, or the synthetic "replace" / "no-op".
	Actions []string
	Before  map[string]interface{}
	After   map[string]interface{}
}

// Load parses terraform plan JSON into normalized changes.
func Load(data []byte) ([]ResourceChange, error) {
	var p tfjson.Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing terraform plan json: %w", err)
	}

	out := make([]ResourceChange, 0, len(p.ResourceChanges))
	for _, rc := range p.ResourceChanges {
		if rc.Change == nil {
			continue
		}
		out = append(out, ResourceChange{
			Address: rc.Address,
			Type:    rc.Type,
			Name:    rc.Name,
			Actions: normalizeActions(rc.Change.Actions),
			Before:  asMap(rc.Change.Before),
			After:   asMap(rc.Change.After),
		})
	}
	return out, nil
}

// normalizeActions collapses terraform's action arrays into a flat list. A
// destroy-then-create (or create-then-destroy) becomes the single synthetic
// action "replace" so destruction rules can match `on: [replace]` directly.
func normalizeActions(a tfjson.Actions) []string {
	switch {
	case a.Replace():
		return []string{"replace"}
	case a.NoOp():
		return []string{"no-op"}
	}
	var out []string
	if a.Create() {
		out = append(out, "create")
	}
	if a.Read() {
		out = append(out, "read")
	}
	if a.Update() {
		out = append(out, "update")
	}
	if a.Delete() {
		out = append(out, "delete")
	}
	return out
}

func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}
