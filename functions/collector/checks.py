"""The pipeline's ten checks, as code (5 starters + 5 custom capstone controls).

Each check reads Cloud Asset Inventory data (already fetched by main.py) and returns
one result per resource: status "pass" or "fail", plus the evidence the decision was
based on. Control mappings live in controls.json, so a check never decides which
framework it satisfies; the crosswalk does.
"""

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
BASIC_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}
REQUIRED_DATA_ACCESS = {"DATA_READ", "DATA_WRITE"}
MIN_WORM_RETENTION_SECONDS = 86400

# Baseline allowlist seeded from Stage 0-6 deployment (includes GCP transitive dependencies).
APPROVED_APIS = {
    "aiplatform.googleapis.com",
    "analyticshub.googleapis.com",
    "apptopology.googleapis.com",
    "artifactregistry.googleapis.com",
    "bigquery.googleapis.com",
    "bigqueryconnection.googleapis.com",
    "bigquerydatapolicy.googleapis.com",
    "bigquerydatatransfer.googleapis.com",
    "bigquerymigration.googleapis.com",
    "bigqueryreservation.googleapis.com",
    "bigquerystorage.googleapis.com",
    "cloudapis.googleapis.com",
    "cloudasset.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "cloudtrace.googleapis.com",
    "containerregistry.googleapis.com",
    "dataform.googleapis.com",
    "dataplex.googleapis.com",
    "datastore.googleapis.com",
    "eventarc.googleapis.com",
    "firebaserules.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "servicemanagement.googleapis.com",
    "serviceusage.googleapis.com",
    "source.googleapis.com",
    "sql-component.googleapis.com",
    "storage-api.googleapis.com",
    "storage-component.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
    "telemetry.googleapis.com",
}


def _result(check_id, resource, passed, evidence):
    return {"check_id": check_id, "resource": resource,
            "status": "pass" if passed else "fail", "evidence": evidence}


def chk_stg_01(buckets, bucket_policies):
    """No public buckets: no allUsers / allAuthenticatedUsers in any bucket binding."""
    out = []
    for name in buckets:
        bindings = bucket_policies.get(name, [])
        public = [b for b in bindings if PUBLIC_MEMBERS & set(b.get("members", []))]
        out.append(_result("CHK-STG-01", name, not public, {"public_bindings": public}))
    return out


def chk_stg_02(buckets):
    """Uniform bucket-level access on for every bucket."""
    out = []
    for name, data in buckets.items():
        ubla = data.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled", False)
        out.append(_result("CHK-STG-02", name, bool(ubla), {"uniformBucketLevelAccess": ubla}))
    return out


def chk_iam_01(project, project_bindings):
    """No service account holds a basic role on the project."""
    bad = [{"role": b["role"], "member": m}
           for b in project_bindings if b.get("role") in BASIC_ROLES
           for m in b.get("members", []) if m.startswith("serviceAccount:")]
    return [_result("CHK-IAM-01", project, not bad, {"basic_role_grants": bad})]


def chk_iam_02(project, keys):
    """No user-managed service account keys: one fail per key, or one project-level pass."""
    user_keys = {name: d for name, d in keys.items() if d.get("keyType") == "USER_MANAGED"}
    if not user_keys:
        return [_result("CHK-IAM-02", project, True, {"user_managed_keys": 0})]
    return [_result("CHK-IAM-02", name, False, {"keyType": d.get("keyType"),
                                                "validAfterTime": d.get("validAfterTime")})
            for name, d in user_keys.items()]


def chk_log_01(project, audit_configs):
    """Data Access logs on for Cloud Storage (or allServices)."""
    types = set()
    for c in audit_configs:
        if c.get("service") in ("storage.googleapis.com", "allServices"):
            types |= {lc.get("logType") for lc in c.get("auditLogConfigs", [])}
    return [_result("CHK-LOG-01", project, REQUIRED_DATA_ACCESS <= types,
                    {"storage_log_types": sorted(t for t in types if t)})]


def chk_stg_03(buckets):
    """Public Access Prevention enforced on every bucket."""
    out = []
    for name, data in buckets.items():
        pap = data.get("iamConfiguration", {}).get("publicAccessPrevention", "inherited")
        out.append(_result("CHK-STG-03", name, pap == "enforced",
                           {"publicAccessPrevention": pap}))
    return out


def chk_stg_04(buckets):
    """Locked WORM retention policy (>= 86400s) on *-reports evidence buckets."""
    out = []
    for name, data in buckets.items():
        if not name.endswith("-reports"):
            continue
        rp = data.get("retentionPolicy", {})
        locked = bool(rp.get("isLocked", False))
        period = int(rp.get("retentionPeriod", 0) or 0)
        passed = locked and period >= MIN_WORM_RETENTION_SECONDS
        out.append(_result("CHK-STG-04", name, passed,
                           {"isLocked": locked, "retentionPeriod": period}))
    return out


def chk_stg_05(buckets):
    """Object versioning enabled on *-tfstate buckets."""
    out = []
    for name, data in buckets.items():
        if not name.endswith("-tfstate"):
            continue
        enabled = bool(data.get("versioning", {}).get("enabled", False))
        out.append(_result("CHK-STG-05", name, enabled, {"versioning_enabled": enabled}))
    return out


def chk_iam_03(run_services, run_policies):
    """No Cloud Run service allows unauthenticated (allUsers/allAuthenticatedUsers) invocation."""
    out = []
    for name in sorted(run_services):
        bindings = run_policies.get(name, [])
        public = [b for b in bindings if PUBLIC_MEMBERS & set(b.get("members", []))]
        out.append(_result("CHK-IAM-03", name, not public, {"public_bindings": public}))
    return out


def chk_api_01(project, enabled_apis):
    """Only approved Google Cloud APIs are enabled; logs full active API inventory."""
    enabled = sorted(enabled_apis)
    unexpected = sorted(set(enabled) - APPROVED_APIS)
    return [_result("CHK-API-01", project, not unexpected, {
        "enabled_count": len(enabled),
        "unexpected_apis": unexpected,
        "enabled_apis": enabled,
    })]
