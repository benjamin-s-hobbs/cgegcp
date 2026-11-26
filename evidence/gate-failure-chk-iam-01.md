# Policy Gate Failure Evidence (`CHK-IAM-01`)

- **Pull Request:** https://github.com/benjamin-s-hobbs/cgegcp/pull/3 (Closed, unmerged)
- **Workflow Run:** https://github.com/benjamin-s-hobbs/cgegcp/actions/runs/45769931634
- **Stage Tested:** `stages/00-foundation`
- **Rule Triggered:** `CHK-IAM-01` (Prohibit basic roles `roles/owner`, `roles/editor`, `roles/viewer`)
- **Auth Method:** Keyless GitHub Actions OIDC via Workload Identity Federation (`GCP_WIF_PROVIDER`)

## Conftest Output

```text
plan-and-check (00-foundation)	Gate	2026-11-26T06:41:49.7457673Z FAIL - stages/00-foundation/plan.json - main - CHK-IAM-01: google_project_iam_member.deliberate_gate_test grants basic role roles/editor. Use a predefined or custom role.
plan-and-check (00-foundation)	Gate	2026-11-26T06:41:49.7458453Z 
plan-and-check (00-foundation)	Gate	2026-11-26T06:41:49.7458778Z 6 tests, 5 passed, 0 warnings, 1 failure, 0 exceptions
plan-and-check (00-foundation)	Gate	2026-11-26T06:41:49.7477243Z ##[error]Process completed with exit code 1.
```
