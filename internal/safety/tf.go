// Package safety implements bumper's enforcement layer: verifying a saved
// Terraform plan (binding a passing scan to the exact plan file by sha256) and
// guarding `terraform apply`/`destroy` as a Claude Code PreToolUse hook, so an
// agent cannot apply a plan nobody verified.
//
// The deterministic core (engine/rules/plan) never imports this package; this is
// the outermost shell.
package safety

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolvePlanData turns a plan reference into `terraform show -json` bytes.
// Inline JSON is used as-is; a path that already holds JSON is read directly;
// any other path is treated as a binary plan and run through `terraform show
// -json`. source is a label describing which path was taken.
func ResolvePlanData(planJSON, path string) (data []byte, source string, err error) {
	if planJSON != "" {
		return []byte(planJSON), "inline", nil
	}
	if path == "" {
		return nil, "", fmt.Errorf("provide either plan JSON or a plan path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if json.Valid(raw) {
		return raw, "json-file", nil
	}
	shown, err := ShowJSON(path)
	if err != nil {
		return nil, "", err
	}
	return shown, "terraform-show", nil
}

// ShowJSON runs `terraform show -json <planPath>` and returns its stdout. It
// degrades with a clear message when terraform is not installed.
func ShowJSON(planPath string) ([]byte, error) {
	bin := terraformBin()
	if bin == "" {
		return nil, fmt.Errorf("%s is not plan JSON and neither 'terraform' nor 'tofu' is on PATH to read the "+
			"binary plan; pass 'terraform show -json' output instead", planPath)
	}
	// terraform must run in the plan's own directory so it can find
	// .terraform/providers and load provider schemas; otherwise `show -json`
	// fails with "Failed to load plugin schemas".
	cmd := exec.Command(bin, "show", "-json", filepath.Base(planPath))
	cmd.Dir = filepath.Dir(planPath)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s show -json %s failed: %v: %s", bin, planPath, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// terraformBin returns "terraform", or "tofu" (OpenTofu) as a fallback, or ""
// if neither is on PATH.
func terraformBin() string {
	for _, b := range []string{"terraform", "tofu"} {
		if _, err := exec.LookPath(b); err == nil {
			return b
		}
	}
	return ""
}

// Sha256File returns the lowercase hex sha256 of a file's contents. This is the
// binding key: the verdict for a plan is stored under the hash of the exact
// bytes that `terraform apply <plan>` will consume.
func Sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
