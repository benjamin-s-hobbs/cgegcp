# Control Catalog & Crosswalk (`cgegcp`)

This document maps every control enforced by the `cgegcp` pipeline to **NIST CSF 2.0** and **NIST SP 800-53 Rev. 5**, documents its data source and pass criteria, and defines the blast radius of automated remediation.

> **Source of truth:** Runtime check metadata lives in `functions/collector/controls.json`, check logic lives in `functions/collector/checks.py`, and preventive plan-time rules live in `policy/`. All five custom controls reuse `grc-collector`'s existing `roles/cloudasset.viewer` snapshot—**zero additional IAM permissions** were granted.

---

## Control Summary Matrix

| Check ID | Control Title | NIST CSF 2.0 | NIST SP 800-53 Rev. 5 | Severity | Coverage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CHK-STG-01` | No Cloud Storage bucket is publicly accessible | `PR.AA-05`, `PR.DS-01` | `AC-3`, `AC-6`, `SC-7` | High | Preventive (`policy/`) + Detective (CAI) + Remediated (Stage 6) |
| `CHK-STG-02` | Uniform bucket-level access is on for every bucket | `PR.AA-05` | `AC-3`, `AC-6` | Medium | Preventive (`policy/`) + Detective (CAI) |
| `CHK-IAM-01` | No service account holds a basic role (Owner, Editor, Viewer) | `PR.AA-05` | `AC-6` | High | Preventive (`policy/`) + Detective (CAI) |
| `CHK-IAM-02` | No service account has a user-managed key | `PR.AA-01` | `IA-5` | High | Preventive (`policy/`) + Detective (CAI) |
| `CHK-LOG-01` | Data Access logs (`DATA_READ`, `DATA_WRITE`) are on for Cloud Storage | `PR.PS-04` | `AU-2`, `AU-12` | Medium | Detective (CAI) |
| `CHK-STG-03` | Public Access Prevention (`enforced`) is on for every bucket | `PR.AA-05`, `PR.DS-01` | `AC-3`, `SC-7` | High | Preventive (`policy/`) + Detective (CAI) |
| `CHK-STG-04` | Locked WORM retention policy (`≥ 86400s`) is on for `*-reports` buckets | `PR.PS-04`, `PR.DS-01` | `AU-9` | High | Detective (CAI) |
| `CHK-STG-05` | Object versioning is enabled on `*-tfstate` buckets | `PR.DS-10`, `PR.IR-01` | `CP-9` | Medium | Detective (CAI) |
| `CHK-IAM-03` | No Cloud Run service allows unauthenticated (`allUsers`/`allAuthenticatedUsers`) invocation | `PR.AA-05` | `AC-3`, `IA-2` | High | Detective (CAI) |
| `CHK-API-01` | Only approved Google Cloud APIs are enabled in the project | `ID.AM-02`, `PR.PS-01` | `CM-7`, `CM-8` | Medium | Detective (CAI) |

---

## Starter Controls (1–5)

### `CHK-STG-01` — No Public Cloud Storage Buckets
* **Mapping:** NIST CSF 2.0 `PR.AA-05`, `PR.DS-01` | NIST SP 800-53 Rev. 5 `AC-3`, `AC-6`, `SC-7`
* **Severity:** High
* **Data Source:** Cloud Asset Inventory `search_all_iam_policies` (`storage.googleapis.com/Bucket`)
* **Pass Condition:** No bucket IAM policy binding grants any role to `allUsers` or `allAuthenticatedUsers`.
* **Engineering Note:** Uses `search_all_iam_policies` rather than `list_assets` because validation showed `search_all_iam_policies` reflects new public grants in ~60 seconds, whereas `list_assets` can lag 4+ minutes.

### `CHK-STG-02` — Uniform Bucket-Level Access Enabled
* **Mapping:** NIST CSF 2.0 `PR.AA-05` | NIST SP 800-53 Rev. 5 `AC-3`, `AC-6`
* **Severity:** Medium
* **Data Source:** Cloud Asset Inventory `list_assets` (`storage.googleapis.com/Bucket`, `RESOURCE`)
* **Pass Condition:** `iamConfiguration.uniformBucketLevelAccess.enabled == true` on every bucket in the project.

### `CHK-IAM-01` — No Service Account Holds a Basic Role
* **Mapping:** NIST CSF 2.0 `PR.AA-05` | NIST SP 800-53 Rev. 5 `AC-6`
* **Severity:** High
* **Data Source:** Cloud Asset Inventory `list_assets` (`cloudresourcemanager.googleapis.com/Project`, `IAM_POLICY`)
* **Pass Condition:** Zero `serviceAccount:*` members hold `roles/owner`, `roles/editor`, or `roles/viewer` at the project level.

### `CHK-IAM-02` — No User-Managed Service Account Keys
* **Mapping:** NIST CSF 2.0 `PR.AA-01` | NIST SP 800-53 Rev. 5 `IA-5`
* **Severity:** High
* **Data Source:** Cloud Asset Inventory `list_assets` (`iam.googleapis.com/ServiceAccountKey`, `RESOURCE`)
* **Pass Condition:** Zero keys have `keyType == "USER_MANAGED"`. Workloads use attached service accounts; GitHub Actions uses Workload Identity Federation (WIF).

### `CHK-LOG-01` — Cloud Storage Data Access Logs Enabled
* **Mapping:** NIST CSF 2.0 `PR.PS-04` | NIST SP 800-53 Rev. 5 `AU-2`, `AU-12`
* **Severity:** Medium
* **Data Source:** Cloud Asset Inventory `list_assets` (`cloudresourcemanager.googleapis.com/Project`, `IAM_POLICY`)
* **Pass Condition:** Project `auditConfigs` enables both `DATA_READ` and `DATA_WRITE` for `storage.googleapis.com` (or `allServices`).

---

## Custom Controls (Capstone Extensions, 6–10)

### `CHK-STG-03` — Public Access Prevention Enforced on Every Bucket
* **Mapping:** NIST CSF 2.0 `PR.AA-05`, `PR.DS-01` | NIST SP 800-53 Rev. 5 `AC-3`, `SC-7`
* **Severity:** High
* **Data Source:** Cloud Asset Inventory `list_assets` (`storage.googleapis.com/Bucket`, `RESOURCE`)
* **Pass Condition:** `iamConfiguration.publicAccessPrevention == "enforced"` on every bucket in the project.
* **Rationale:** `CHK-STG-01` detects buckets that are *currently* public; `CHK-STG-03` verifies the preventive guardrail that blocks future public grants, establishing 1:1 runtime parity with the OPA/Conftest gate.

### `CHK-STG-04` — Locked WORM Retention Policy on Evidence Buckets
* **Mapping:** NIST CSF 2.0 `PR.PS-04`, `PR.DS-01` | NIST SP 800-53 Rev. 5 `AU-9`
* **Severity:** High
* **Data Source:** Cloud Asset Inventory `list_assets` (`storage.googleapis.com/Bucket`, `RESOURCE`)
* **Pass Condition:** Every bucket matching `*-reports` has `retentionPolicy.isLocked == true` and `int(retentionPeriod) >= 86400`.
* **Rationale:** Converts the one-time Lab 4 WORM verification (`evidence/01-retention-delete-denied.txt`) into a continuous daily control proving audit artifacts remain immutable.

### `CHK-STG-05` — Object Versioning Enabled on Terraform State Buckets
* **Mapping:** NIST CSF 2.0 `PR.DS-10`, `PR.IR-01` | NIST SP 800-53 Rev. 5 `CP-9`
* **Severity:** Medium
* **Data Source:** Cloud Asset Inventory `list_assets` (`storage.googleapis.com/Bucket`, `RESOURCE`)
* **Pass Condition:** Every bucket matching `*-tfstate` has `versioning.enabled == true`.
* **Rationale:** Protects Terraform remote state from accidental overwrite or corruption, preserving IaC recoverability without generating noise on ephemeral buckets.

### `CHK-IAM-03` — No Public Cloud Run Invokers
* **Mapping:** NIST CSF 2.0 `PR.AA-05` | NIST SP 800-53 Rev. 5 `AC-3`, `IA-2`
* **Severity:** High
* **Data Source:** Cloud Asset Inventory `search_all_iam_policies` (`run.googleapis.com/Service`)
* **Pass Condition:** Zero Cloud Run services (`grc-collector`, `grc-reporter`, `grc-narrator`, `grc-remediator`) grant any role to `allUsers` or `allAuthenticatedUsers`.
* **Rationale:** Protects the pipeline's own control plane, ensuring Cloud Functions v2 services are strictly invocable via authenticated OIDC tokens from `grc-scheduler`. Uses `search_all_iam_policies` to avoid `list_assets` IAM indexing lag.

### `CHK-API-01` — Approved Google Cloud APIs Only (Least Functionality)
* **Mapping:** NIST CSF 2.0 `ID.AM-02`, `PR.PS-01` | NIST SP 800-53 Rev. 5 `CM-7`, `CM-8`
* **Severity:** Medium
* **Data Source:** Cloud Asset Inventory `list_assets` (`serviceusage.googleapis.com/Service`, `RESOURCE`)
* **Pass Condition:** Every `ENABLED` API in the project appears in the explicit Stage 0–6 allowlist (seeded from the known-good baseline, including GCP transitive dependencies such as Cloud Run, Cloud Build, Artifact Registry, and Eventarc).
* **Rationale:** Closes the loop on Stage 0's "APIs as code" design by catching shadow/manual API enablement at runtime. Even on a `pass`, the check records the full `enabled_apis` list and count in Firestore `evidence`, providing a daily timestamped API inventory.

---

## Remediator Blast-Radius Notes (`grc-remediator`)

Automated remediation in Stage 6 (`stages/06-enforcement`) is intentionally constrained to **`CHK-STG-01`** only:

* **Identity:** Runs as dedicated service account `grc-remediator`.
* **Custom Role (`grcBucketRemediator`):** Grants exactly four storage permissions—`storage.buckets.get`, `storage.buckets.getIamPolicy`, `storage.buckets.setIamPolicy`, and `storage.buckets.update`—plus `roles/datastore.user` for reading `assessments` and writing `remediations` in Firestore.
* **What it can do:** Strip `allUsers`/`allAuthenticatedUsers` bindings from a failing bucket and set `public_access_prevention = "enforced"`.
* **What it cannot do:** Delete buckets or objects, read object contents, modify project-level IAM, or touch any non-Storage GCP resource.
* **Escalation Ladder:** Deployed in `approve` mode (Rung 2, promoted via reviewed PR `#6`), requiring explicit human approval via `labs/06-loop/approve.py` before mutating any bucket. Recurring violations on previously `fixed` buckets automatically reopen as `pending_approval`.
