package engine_test

import "testing"

// TestGCPIAMRoles covers the GCP IAM hardening rule set: primitive roles,
// user-managed SA keys, impersonation/escalation roles at broad scope, and
// roles granted to default service accounts — with discriminating negatives
// (roles/viewer, a scoped grant to a normal SA, normal users, and a
// non-default SA member alongside a default one).
func TestGCPIAMRoles(t *testing.T) {
	f := evalFixture(t, "plan_gcp_iam_roles.json")

	// Positive cases — each rule must fire on the intended resource.
	for _, c := range []struct{ rule, addr string }{
		{"GCP_IAM_PRIMITIVE_ROLE", "google_project_iam_member.owner"},
		{"GCP_IAM_PRIMITIVE_ROLE", "google_organization_iam_binding.editor"},
		{"GCP_SERVICE_ACCOUNT_KEY", "google_service_account_key.deploy"},
		{"GCP_IAM_SA_IMPERSONATION_ROLE", "google_folder_iam_member.tokencreator"},
		{"GCP_IAM_SA_IMPERSONATION_ROLE", "google_project_iam_binding.sa_user"},
		{"GCP_IAM_DEFAULT_SA_GRANT", "google_project_iam_member.default_compute"},
		{"GCP_IAM_DEFAULT_SA_GRANT", "google_folder_iam_binding.default_appspot"},
	} {
		if !has(f, c.rule, c.addr) {
			t.Errorf("expected finding %s on %s; got %+v", c.rule, c.addr, f)
		}
	}

	// Negative cases — these resources must produce no findings at all.
	for _, addr := range []string{
		"google_project_iam_member.viewer",        // roles/viewer is not primitive owner/editor
		"google_project_iam_member.scoped",        // benign predefined role to a normal SA
		"google_project_iam_binding.normal_users", // normal user + non-default SA members
	} {
		if mentions(f, addr) {
			t.Errorf("resource %s should produce no findings; got %+v", addr, f)
		}
	}
}
