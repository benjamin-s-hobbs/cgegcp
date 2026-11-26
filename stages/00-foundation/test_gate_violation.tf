# Deliberate CHK-IAM-01 violation to verify OPA/Conftest policy gate blocks basic roles.
# This PR is intended to fail CI and be closed without merging.
resource "google_project_iam_member" "deliberate_gate_test" {
  project = var.project_id
  role    = "roles/editor"
  member  = "user:gate-test@example.com"
}
