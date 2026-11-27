resource "google_storage_bucket" "loose" {
  name     = "${var.project_id}-loose"
  location = "us-central1"
}

resource "google_service_account_key" "nope" {
  service_account_id = "grc-collector@${var.project_id}.iam.gserviceaccount.com"
}
