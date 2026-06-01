package engine_test

import "testing"

// TestGCPComputeHardening covers the Compute Engine instance hardening rule set:
// Shielded VM Secure Boot off (only when the block is present), interactive
// serial-port access enabled ("true" and "1"), an explicit OS Login disable, and
// the absence-based project-wide-SSH-keys advisory. Negatives include the secure
// values for each control plus a fully hardened instance that must be silent.
func TestGCPComputeHardening(t *testing.T) {
	f := evalFixture(t, "plan_gcp_compute_hardening.json")

	// Positive cases.
	for _, c := range []struct{ rule, addr string }{
		{"GCP_COMPUTE_SHIELDED_SECURE_BOOT_OFF", "google_compute_instance.secureboot_off"},
		{"GCP_COMPUTE_SERIAL_PORT_ENABLED", "google_compute_instance.serial_on"},
		{"GCP_COMPUTE_SERIAL_PORT_ENABLED", "google_compute_instance.serial_on_numeric"},
		{"GCP_COMPUTE_OS_LOGIN_DISABLED", "google_compute_instance.oslogin_off"},
		// Advisory absence-based rule: fires when block-project-ssh-keys is not "true".
		{"GCP_COMPUTE_PROJECT_SSH_KEYS_ALLOWED", "google_compute_instance.no_block_keys"},
		{"GCP_COMPUTE_PROJECT_SSH_KEYS_ALLOWED", "google_compute_instance.no_metadata"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — these must produce no findings at all.
	for _, addr := range []string{
		"google_compute_instance.secureboot_on",     // secure boot on, all metadata secure
		"google_compute_instance.no_shielded_block", // no shielded block => secure-boot rule must not fire
		"google_compute_instance.hardened",          // fully hardened, silent everywhere
	} {
		if mentions(f, addr) {
			t.Errorf("resource %s should produce no findings; got %+v", addr, f)
		}
	}
}
