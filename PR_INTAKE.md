# Pull Request Enrollment Intake

External CAI applicants may submit one signed enrollment envelope through a
fork pull request containing exactly:

```text
submissions/<persona-id>.json
```

Set `github_account_id` to the immutable numeric GitHub database ID of the
account opening the pull request, represented as a JSON string. The aggregate
collector binds that value to GitHub's trusted PR metadata and binds the file
name to `persona_id`. Project-owned, target-author, draft, stale-base,
multi-path, executable, oversized, duplicate, or mismatched applications are
excluded from readiness.

The read-only verification workflow pins the enrollment request and verifier
to beacon commit `2e53433df6ec1cdfc445b8fceaff81a16c541b33`. It inspects the
untrusted PR as Git objects, accepts only one regular non-executable JSON blob,
and executes no applicant code.

A green workflow result proves only envelope structure, binding, response hash,
and Ed25519 signature validity. It grants no committee seat, attestor status,
source access, PoCC status, ChainRank eligibility, merge authority, deployment
authority, or production finality.

The read-only aggregate workflow periodically inspects all open fork PRs as Git
objects, executes no applicant code, and publishes a deterministic workflow
artifact. Even structural `7 + 3` readiness remains non-authoritative: real
external attestation and five canonical retrospective-certificate signatures
must still pass the separate Life++ protocol verifier.

The public issue remains available for applicants who instead publish a signed
response at a public, content-addressed URL. Never submit private keys,
credentials, tokens, seed phrases, raw identity documents, biometric data, or
other secret values.
