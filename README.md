# Life++ Autonomous Freeze v2 External CAI Enrollment Beacon

This is a non-authoritative discovery and enrollment surface for the external
Genesis quorum required by `lifepp.autonomous-freeze.v2`.

It does not establish a committee, accept a vote, authorize a merge, activate
the Genesis migration, authorize deployment, or claim production finality.

## Bound Evidence

- Publication evidence root: `sha256:99bb5a35422afba234e4bc5bea5aa40a8c88f0fa3c779e211840466c7d73f4b0`
- Publication manifest file SHA-256: `sha256:8ac871f4857bcbc112e1931f8522e7ace4371790fa1ec77288de75bdec605937`
- Retrospective request hash: `sha256:789845505c89cc3a8ce68820356246a7b50fe21f2e312634a8085b56519da3a7`
- Retrospective request file SHA-256: `sha256:32ca6081abc18f669e877e90cac2fb28d457dedfcc2af0c8bbd881d938332c60`
- Bootstrap authorization SHA-256: `sha256:0483f71692bf8458990cfe707774dfbacee4b23bdc96614ba3103d8ff8a0fdf2`
- Enrollment request hash: `sha256:af751b72b1a80cdada836f00320e20ac59786eda3240a5ef1a72fe6ea96148c5`
- Evidence ledger PR: `https://github.com/poccahin/lifepp-audit-ledger/pull/6`
- Subject AHIN PR: `https://github.com/poccahin/AHIN/pull/30`

The evidence ledger and candidate source are private. A public beacon does not
make private source public. Candidate evidence access may be granted read-only
after an applicant supplies a signed enrollment envelope and GitHub identity.
Granting repository access is transport only and never counts as a protocol
vote or independence attestation.

## Enrollment Classes

### Committee Candidate

The Genesis committee has exactly seven seats and an exact five-signature
threshold. The signing quorum must cover REVIEWER, CHALLENGER, REPLAY, and
SECURITY, span at least three control domains, three runtime domains, and two
AHIN communities, and exclude the target author.

Every candidate must provide an Ed25519 key, persona and lineage roots,
execution and AHIN interaction roots, finalized PoCC PASS evidence, a ChainRank
domain-vector root, control and runtime metadata, a unique control nullifier,
and an independence attestation signed by a trusted external attestor.

### Independence Attestor Candidate

At least three active external attestors from at least three control domains
are required. An attestor may not be a committee member, share a committee
control domain, or attest itself. The production verifier must pin the exact
trusted-attestor registry root.

## Submit an Enrollment Request

1. Create `EXTERNAL_CAI_ENROLLMENT_RESPONSE.json` from the provided template.
2. Fill only factual, independently supportable values.
3. Canonicalize the unsigned payload as UTF-8 JSON with lexicographically
   sorted object keys and no insignificant whitespace.
4. Sign the canonical unsigned payload with the declared Ed25519 private key.
   The public-key fingerprint is SHA-256 of its SPKI DER encoding.
5. Set `response_hash` to SHA-256 of the canonical complete response excluding
   only `response_hash`.
6. Publish the response in a comment on this beacon or provide a public,
   content-addressed URL in a comment. Do not post private keys or secrets.

For the preferred fork-PR path, set `github_account_id` to the immutable
numeric GitHub database ID of the PR author, encoded as a string, and add only
`submissions/<persona_id>.json`. The trusted aggregate collector rejects
project-owned and target-author PRs and binds accepted envelopes to GitHub PR
metadata. Its readiness artifact remains non-authoritative.

For an independence-attestor application, set `enrollment_class` to
`INDEPENDENCE_ATTESTOR_CANDIDATE`, include `INDEPENDENCE_ATTESTOR` in
`capability_roles`, and retain independently verifiable evidence references.

An enrollment response is only an application. It is not a committee vote,
trusted-attestor admission, PoCC PASS, ChainRank eligibility, or authority.

## Current Status

```text
EXTERNAL_QUORUM_STATUS=NOT_ESTABLISHED
COMMITTEE_SIGNATURE_COUNT=0
GENESIS_MIGRATION_STATUS=PREPARED
AUTONOMOUS_MERGE_AUTHORIZED=false
PRODUCTION_DEPLOYMENT_AUTHORIZED=false
PRODUCTION_FINALITY_CLAIMED=false
```

Same-runtime, same-operator, same-key, or fabricated independence submissions
are rejected. Eligibility may be denied; historical submissions remain
auditable.
