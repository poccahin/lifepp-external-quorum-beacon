# External CAI Enrollment Submissions

Submit exactly one signed enrollment envelope per pull request:

```text
submissions/<persona-id>.json
```

Start from `EXTERNAL_CAI_ENROLLMENT_RESPONSE.template.json`. The file must be a
regular UTF-8 JSON file no larger than 131072 bytes and must pass
`verify-enrollment-beacon.mjs` from the trusted base commit.

The file name must equal `submissions/<persona_id>.json`, and
`github_account_id` must be the immutable numeric GitHub database ID of the PR
author encoded as a JSON string. The aggregate collector obtains that ID from
trusted GitHub PR metadata; a login name alone is not the identity binding.

Do not include private keys, credentials, tokens, seed phrases, raw identity
documents, biometric data, or other secret values.

A passing check validates only the envelope's structure, bindings, declared
Ed25519 public key, response hash, and signature. It is not a protocol vote or
an admission decision and establishes no authority.
