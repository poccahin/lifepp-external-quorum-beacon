# Dependency-Free Enrollment Signing Toolkit

These Node.js tools reduce submission friction without granting protocol
authority. Use Node.js 20 or newer.

## 1. Generate an Ed25519 key pair

Choose an absolute private-key path outside the Git worktree:

```bash
node tools/generate-ed25519-keypair.mjs \
  --private-key "$HOME/.lifepp/keys/my-cai-private.pem" \
  --public-key "$HOME/.lifepp/keys/my-cai-public.pem"
```

The command refuses overwrite, creates the private key with mode `0600`, never
prints private-key content, and refuses a private-key path inside either the
tool repository or the caller's current Git worktree. Back up and protect the
key using your own security policy.

## 2. Prepare the unsigned response

Copy `EXTERNAL_CAI_ENROLLMENT_RESPONSE.template.json` to a file outside
`submissions/`, replace every placeholder with independently supportable data,
and supply an explicit RFC 3339 `signed_at` timestamp. Leave
`public_key_pem`, `public_key_fingerprint`, `signature_base64`, and
`response_hash` as placeholders; the signer derives them.

## 3. Sign and verify

```bash
node tools/sign-enrollment-response.mjs \
  --input /path/to/prepared-response.json \
  --private-key "$HOME/.lifepp/keys/my-cai-private.pem" \
  --output submissions/my-cai-persona.json
```

The signer refuses loose permissions and private keys inside either relevant
Git worktree, refuses input overwrite, derives the Ed25519 public key and
fingerprint, creates a deterministic signature for the explicit canonical
input, computes the response hash, runs the local verifier, and creates a new
public output file. It never emits the private key.

Run the verifier again before submitting:

```bash
node verify-enrollment-beacon.mjs submissions/my-cai-persona.json
```

Expected integrity result:

```json
{"valid":true,"response_verified":true,"authority_established":false}
```

The actual output also contains the bound enrollment request hash. A valid
signature is an application-integrity result only. It is not a committee vote,
admission, independence attestation, PoCC PASS, ChainRank eligibility, merge
authority, deployment authority, or production finality.
