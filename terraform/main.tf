terraform {
  backend "gcs" {
    bucket = "tf-state-afr-operator-5560235161"
    prefix = "terraform/state"
  }
}


locals {
  project = "afr-operator-5560235161"
}



resource "google_project_service" "iam" {
  project            = local.project
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "workload-identity-federation" {
  project            = local.project
  service            = "sts.googleapis.com"
  disable_on_destroy = false
}

resource "google_iam_workload_identity_pool" "pool" {
  workload_identity_pool_id = "afr-operator-pool"
  display_name              = "afr-operator-pool"
  description               = "Created By OpenShift ccoctl"
  project                   = local.project

  depends_on = [google_project_service.workload-identity-federation]
}

resource "google_iam_workload_identity_pool_provider" "provider" {
  #checkov:skip=CKV_GCP_118:Allow any identity to authenticate
  project                            = local.project
  display_name                       = "afr-operator-provider"
  description                        = "afr-operator-provider"
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "afr-operator-provider"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    issuer_uri        = "https://storage.googleapis.com/okd-homelab-wif-oidc"
    allowed_audiences = ["openshift"]
  }
}

resource "google_service_account" "wif_test" {
  project      = local.project
  account_id   = "wif-test"
  display_name = "wif-test"
}

data "google_project" "project" {
  project_id = local.project
}

resource "google_service_account_iam_member" "wif_test_wif_binding" {
  service_account_id = google_service_account.wif_test.id
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.pool.workload_identity_pool_id}/subject/system:serviceaccount:smoke-tests:wif-test"
}
