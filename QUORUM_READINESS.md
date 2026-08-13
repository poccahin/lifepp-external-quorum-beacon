# Non-Authoritative Quorum Readiness Check

`tools/check-quorum-readiness.mjs` evaluates a set of signed enrollment
applications without promoting those applications to protocol votes.

```bash
node tools/check-quorum-readiness.mjs submissions/*.json
```

Run the deterministic simulation and negative-control matrix with:

```bash
node tools/test-quorum-readiness.mjs
```

Open fork PRs are aggregated by the read-only workflow using:

```bash
node tools/materialize-open-enrollment-prs.mjs ...
node tools/build-open-enrollment-readiness.mjs ...
```

The collector binds each signed envelope to the immutable GitHub database ID
of its PR author and to `submissions/<persona_id>.json`. It reads untrusted PRs
as Git objects and never checks out or executes applicant content. Run its
local Git-object and adversarial matrix with:

```bash
node tools/test-open-enrollment-collector.mjs
```

The checker first hash-pins and runs the single-application verifier on every input.
It then searches for a claimed structural candidate set containing:

- seven committee candidates;
- a five-member signer subset;
- at least three claimed control domains;
- at least three claimed runtime domains;
- at least two claimed AHIN communities;
- reviewer, challenger, replay, and security roles;
- no identity or control field that alone reaches the five-seat threshold;
- three external attestor candidates from three claimed control domains that
  do not overlap the selected committee control domains.

Input order does not affect the report. The report contains no wall-clock
field, and identical verified applications produce byte-identical output.

## Boundary

This is a transport-readiness check, not an independence oracle. Unique strings
and valid application signatures do not prove independent control. Even a
`STRUCTURALLY_READY_FOR_EXTERNAL_ATTESTATION_AND_CERTIFICATE_SIGNING` result
keeps:

```text
actual_certificate_signature_count=0
external_quorum_status=NOT_ESTABLISHED
independence_verified=false
protocol_authority=false
```

External attestors must still verify evidence, and five eligible committee
members must still sign the canonical retrospective certificate accepted by
the Life++ protocol verifier. This checker cannot activate migration, merge a
change, deploy software, or establish production finality.
