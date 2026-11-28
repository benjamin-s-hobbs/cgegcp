# cgegcp — Automated GRC Engineering Pipeline on Google Cloud

**Tenancy assumption:** One standalone Google Cloud project (`cgegcp-bsh`) on a personal `@gmail.com` account, with no Google Cloud Organization or Folder hierarchy above it. Nothing in this repository requires an Organization; for enterprise org-level patterns, see `docs/APPENDIX-ORGANIZATION.md`.

This repository implements an end-to-end, seven-stage **Governance, Risk, and Compliance (GRC) Engineering** pipeline on Google Cloud Platform for the **Certified GRC Engineer – GCP (CGE-GCP)** capstone. It combines preventive Policy-as-Code (`OPA`/`Conftest`), detective Cloud Asset Inventory monitoring, immutable WORM evidence storage, Firestore-backed OSCAL/ATO reporting, optional Gemini executive narratives, and human-in-the-loop automated remediation.

---

## Architecture & Pipeline Stages

Each stage is an isolated Terraform root module with its own remote state prefix in Cloud Storage, pinned provider versions, additive IAM (`*_iam_member` only), and `disable_on_destroy = false` on project APIs.

| Stage | Directory | Purpose | Runtime Identity |
| :--- | :--- | :--- | :--- |
| **0** | `stages/00-foundation` | Enables required GCP APIs as code; creates 6 dedicated service accounts with zero initial permissions | Operator / CI |
| **1** | `stages/01-discovery` | Read-only baseline discovery; outputs a configuration gap map without mutating resources | Operator / CI (read-only) |
| **2** | `stages/02-activation` | Closes measured gaps: enables GCS Data Access logs, 365-day audit log bucket, and log sink | Operator |
| **3** | `stages/03-evidence-store` | Provisions Firestore evidence store, WORM-locked reports bucket, and daily collector running **10 checks** | `grc-collector` |
| **4** | `stages/04-reporting` | Generates POA&M (CSV/JSON), SAR (Markdown), and OSCAL 1.1.2 SSP (JSON) strictly from Firestore | `grc-reporter` |
| **5** | `stages/05-narrative` | Optional Vertex AI (Gemini) weekly executive digest; summarizes reports without making compliance decisions | `grc-narrator` |
| **6** | `stages/06-enforcement` | Remediates public GCS buckets (`CHK-STG-01`) on an escalation ladder (`report_only` → `approve` → `auto`) | `grc-remediator` |

---

## Capstone Differentiators

Beyond the five starter checks, this implementation hardens both the control plane and the runtime pipeline:

1. **10 Runtime Controls (5 Starters + 5 Custom Checks, Zero IAM Expansion):**
   All five custom checks reuse `grc-collector`'s existing `roles/cloudasset.viewer` snapshot—no additional IAM permissions were granted:
   * **`CHK-STG-03`** — Enforces `publicAccessPrevention = "enforced"` on every GCS bucket (1:1 runtime parity with the preventive Conftest rule).
   * **`CHK-STG-04`** — Continuously verifies WORM retention lock (`isLocked = true`, `≥ 86400s`) on `*-reports` evidence buckets (`AU-9`).
   * **`CHK-STG-05`** — Verifies object versioning is enabled on `*-tfstate` buckets to protect IaC state integrity (`CP-9`).
   * **`CHK-IAM-03`** — Audits Cloud Run services via `search_all_iam_policies` to ensure no pipeline function allows unauthenticated (`allUsers`/`allAuthenticatedUsers`) invocation (`AC-3`, `IA-2`).
   * **`CHK-API-01`** — Enforces Least Functionality (`CM-7`, `CM-8`) by auditing enabled `serviceusage.googleapis.com/Service` APIs against an explicit allowlist and logging the full active API inventory to Firestore on every run.
2. **Hardened `main` Branch Protection:**
   Configured GitHub branch protection on `main` requiring all **7 `gate/plan-and-check` matrix jobs** (`00-foundation` through `06-enforcement`) to pass before merge, with `enforce_admins: true` so even the repository owner cannot bypass the OPA/Conftest gate.
3. **Human-Approved Remediation (`approve` Mode) & Recurrence Testing:**
   Escalated `grc-remediator` from `report_only` to `approve` via reviewed PR (`#6`), verified human approval via `labs/06-loop/approve.py`, and validated that a recurring violation on a previously `fixed` bucket reopens as `pending_approval`.

---

## Key Design Choices & Engineering Rationale

* **Zero Stored Credentials & Separation of Duties (SoD):**
  GitHub Actions authenticates exclusively via **Workload Identity Federation (WIF)**—zero service account keys exist anywhere in the project or repo. Every pipeline stage runs as its own dedicated service account with least-privilege roles. Notably, `grc-reporter` holds `roles/datastore.viewer` (read-only) and cannot alter assessment results in Firestore, proved in `evidence/02-reporter-write-denied.txt`.
* **Immutable Evidence (WORM) & Deterministic Lineage:**
  The reports bucket (`*-reports`) enforces a locked 24-hour retention policy (`isLocked: true`), preventing tampering or premature deletion (`evidence/01-retention-delete-denied.txt`). Every collector run stamps a UUID `run_id` and `collected_at` timestamp, using deterministic document IDs (`<check_id>_<sha256(resource)[:16]>`) so POA&M aging (`first_failed_at`) stays accurate across daily runs.
* **Least-Privilege Remediation Blast Radius:**
  `grc-remediator` is bound to a custom role (`grcBucketRemediator`) with only four storage permissions (`get`, `getIamPolicy`, `setIamPolicy`, `update`) plus `roles/datastore.user`. It cannot delete buckets, modify IAM on projects, or touch non-storage resources. See `docs/CONTROLS.md` for full blast-radius notes.
* **Rung Escalation via Pull Request (`variables.tf` vs. `.tfvars`):**
  In this single-project repo, `.gitignore` excludes `*.tfvars` to prevent accidental commits of personal project IDs, and `gate.yml` plans without `-var-file`. Raising `mode` from `report_only` to `approve` in `stages/06-enforcement/variables.tf` ensured both GitHub Actions and local applies shared one reviewed source of truth. *Production note:* In multi-environment enterprise repos, `variables.tf` should keep the safest default (`report_only`) while environment-scoped `.tfvars` or `TF_VAR_mode` overrides control promotion.
* **Cloud Eventual Consistency & Race Conditions:**
  Live validation surfaced three GCP eventual-consistency behaviors worth designing around:
  1. *IAM propagation lag:* Triggering Cloud Scheduler jobs seconds after `terraform apply` can return gRPC `CODE: 7` (`PERMISSION_DENIED`) until `roles/run.invoker` propagates (~30s).
  2. *Async job chaining:* `gcloud scheduler jobs run` is asynchronous; triggering `grc-digest-weekly` before `poam`/`sar` finish writing to GCS causes `CODE: 10` (`ABORTED`). Production pipelines should orchestrate dependent jobs via Cloud Workflows rather than tightly spaced cron schedules.
  3. *Asset Inventory indexing:* `search_all_iam_policies` reflects bucket IAM changes in ~60s, whereas `list_assets` can lag 4+ minutes—which is why `CHK-STG-01` and `CHK-IAM-03` query the search API.
* **Transitive API Dependencies (`CHK-API-01`):**
  Enabling high-level GCP services (such as Cloud Functions v2) automatically enables transitive dependencies (Cloud Run, Cloud Build, Artifact Registry, Eventarc). `CHK-API-01`'s allowlist is seeded from the known-good Stage 0–6 baseline so legitimate dependencies do not create alert fatigue while manual/shadow API enablement is immediately flagged.

---

## Cold-Start Deployment Guide (Empty Project)

### Prerequisites
* A GCP project with billing enabled (personal `@gmail.com` account, no Organization required).
* Tools installed locally: `gcloud`, `terraform` (`>= 1.6`), `conftest`, `gitleaks`, `gh` CLI, and Python 3.12 (`python3 -m venv .venv && .venv/bin/pip install -r labs/requirements.txt`).
* Authenticate locally: `gcloud auth login && gcloud auth application-default login`.

### 1. Bootstrap Remote State & Variables
Create a versioned GCS bucket for Terraform state (`<PROJECT_ID>-tfstate`) and configure `labs/03-foundation/backend.hcl` with `bucket = "<PROJECT_ID>-tfstate"`. Pass your project ID via `-var="project_id=<PROJECT_ID>"` (or a gitignored `terraform.tfvars` per stage).

### 2. Deploy Stages in Order (`00` → `06`)
Run `init` and `apply` sequentially so each stage can read the prior stage's outputs and service accounts:

```bash
for stage in \
  00-foundation \
  01-discovery \
  02-activation \
  03-evidence-store \
  04-reporting \
  05-narrative \
  06-enforcement; do
  terraform -chdir="stages/$stage" init -backend-config="../../labs/03-foundation/backend.hcl"
  terraform -chdir="stages/$stage" apply -var="project_id=<PROJECT_ID>"
done
```

### 3. Arm CI/CD Workflows & Branch Protection
1. Run the WIF bootstrap in `labs/02-ci/` to connect GitHub Actions (`gate.yml` and `drift.yml`) to GCP without static keys.
2. Enable GitHub branch protection on `main` requiring all 7 `gate/plan-and-check (<stage>)` checks with `enforce_admins: true`.

### 4. Trigger & Verify the Loop
```bash
# Run daily collector, then reporting & narrative (allowing ~15s between async steps)
gcloud scheduler jobs run grc-collect-daily --location=us-central1
sleep 20
gcloud scheduler jobs run grc-report-ssp --location=us-central1
gcloud scheduler jobs run grc-report-sar --location=us-central1
gcloud scheduler jobs run grc-report-poam --location=us-central1
sleep 20
gcloud scheduler jobs run grc-digest-weekly --location=us-central1
```

---

## Evidence & Local Verification

Run the mechanical rubric check before any submission:
```bash
./self-check.sh
```

Committed compliance proofs live in `evidence/`:
* `evidence/01-retention-delete-denied.txt` — WORM retention lock (`isLocked: true`) blocking object deletion.
* `evidence/02-reporter-write-denied.txt` — Separation of Duties (`403 PERMISSION_DENIED` when `grc-reporter` attempts a Firestore write).
* `evidence/03-gate-failed.txt` — Preventive OPA/Conftest gate blocking `CHK-STG-01`, `CHK-STG-02`, and `CHK-IAM-02` on a closed test PR.

---

## Teardown

Destroy stages in reverse order (`06-enforcement` down to `00-foundation`). Because `*-reports` has a locked 24-hour WORM retention policy, wait until objects age out before deleting the reports and state buckets:
```bash
gcloud storage rm --recursive gs://<PROJECT_ID>-reports
gcloud storage rm --recursive gs://<PROJECT_ID>-tfstate
```