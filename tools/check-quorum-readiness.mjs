import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {lstatSync, readFileSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const VERIFIER = resolve(SCRIPT_DIRECTORY, "..", "verify-enrollment-beacon.mjs");
const PINNED_VERIFIER_SHA256 =
  "ba751fbd9664852f30647668f5e5ff03d189a992b47775e60273c7411f814b44";
const MAX_APPLICATIONS = 16;
const MAX_APPLICATION_BYTES = 131072;
const REQUIRED_ROLES = Object.freeze(["REVIEWER", "CHALLENGER", "REPLAY", "SECURITY"]);
const QUORUM_CONTROL_FIELDS = Object.freeze([
  "github_account_id",
  "operator_id",
  "model_provider_id",
  "runtime_domain_id",
  "control_domain_id",
  "runtime_image_digest",
  "public_key_fingerprint",
  "control_nullifier",
]);
const UNIQUE_IDENTITY_FIELDS = Object.freeze([
  "response_hash",
  "persona_id",
  "public_key_fingerprint",
  "control_nullifier",
]);

const fail = (code, message) => {
  const error = new Error(message);
  error.code = code;
  throw error;
};

const canonical = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};

const sha256 = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function* combinations(values, count, start = 0, prefix = []) {
  if (prefix.length === count) {
    yield prefix;
    return;
  }
  const remaining = count - prefix.length;
  for (let index = start; index <= values.length - remaining; index += 1) {
    yield* combinations(values, count, index + 1, [...prefix, values[index]]);
  }
}

const distinctCount = (members, field) =>
  new Set(members.map((member) => member[field])).size;

const controlsThreshold = (members, field, threshold) => {
  const counts = new Map();
  for (const member of members) {
    counts.set(member[field], (counts.get(member[field]) ?? 0) + 1);
  }
  return [...counts.values()].some((count) => count >= threshold);
};

const hasRoleCoverage = (members) => {
  const roles = new Set(members.flatMap((member) => member.capability_roles));
  return REQUIRED_ROLES.every((role) => roles.has(role));
};

const signerSetQualifies = (members) =>
  members.length === 5 &&
  distinctCount(members, "control_domain_id") >= 3 &&
  distinctCount(members, "runtime_domain_id") >= 3 &&
  distinctCount(members, "ahin_community_id") >= 2 &&
  hasRoleCoverage(members) &&
  QUORUM_CONTROL_FIELDS.every((field) => !controlsThreshold(members, field, 5));

const committeeQualifies = (members) =>
  members.length === 7 &&
  QUORUM_CONTROL_FIELDS.every((field) => !controlsThreshold(members, field, 5));

const externalAttestorSet = (attestors, committee) => {
  const committeePersonas = new Set(committee.map(({persona_id}) => persona_id));
  const committeeControlDomains = new Set(committee.map(({control_domain_id}) => control_domain_id));
  const eligible = attestors.filter((attestor) =>
    !committeePersonas.has(attestor.persona_id) &&
    !committeeControlDomains.has(attestor.control_domain_id));
  for (const selection of combinations(eligible, 3)) {
    if (distinctCount(selection, "control_domain_id") >= 3) return selection;
  }
  return null;
};

const verifyApplication = (path) => {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail("APPLICATION_NOT_REGULAR_FILE", "application must be a regular file");
  }
  if (stat.size > MAX_APPLICATION_BYTES) {
    fail("APPLICATION_TOO_LARGE", "application exceeds the 131072-byte limit");
  }
  const verification = spawnSync(process.execPath, [VERIFIER, path], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  if (verification.status !== 0 || verification.signal !== null || verification.error) {
    fail(
      "APPLICATION_INTEGRITY_VERIFICATION_FAILED",
      verification.stderr.trim() || "signed application failed integrity verification",
    );
  }
  const result = JSON.parse(verification.stdout);
  if (result.valid !== true || result.response_verified !== true ||
      result.authority_established !== false) {
    fail("FAIL_CLOSED_APPLICATION_RESULT", "application verifier returned an unsafe result");
  }
  return JSON.parse(readFileSync(path, "utf8"));
};

const paths = process.argv.slice(2);
if (createHash("sha256").update(readFileSync(VERIFIER)).digest("hex") !==
    PINNED_VERIFIER_SHA256) {
  fail("PINNED_VERIFIER_MISMATCH", "single-application verifier bytes do not match the pin");
}
if (paths.length > MAX_APPLICATIONS) {
  fail("TOO_MANY_APPLICATIONS", `at most ${MAX_APPLICATIONS} applications may be checked`);
}

const applications = paths.map((path) => verifyApplication(resolve(path)))
  .sort((left, right) => left.response_hash.localeCompare(right.response_hash));
for (const field of UNIQUE_IDENTITY_FIELDS) {
  if (distinctCount(applications, field) !== applications.length) {
    fail("DUPLICATE_APPLICATION_IDENTITY", `duplicate ${field} is not eligible for readiness`);
  }
}

const committeeCandidates = applications.filter(({enrollment_class}) =>
  enrollment_class === "COMMITTEE_CANDIDATE");
const attestorCandidates = applications.filter(({enrollment_class}) =>
  enrollment_class === "INDEPENDENCE_ATTESTOR_CANDIDATE");

let selected = null;
if (committeeCandidates.length >= 7) {
  selection:
  for (const signers of combinations(committeeCandidates, 5)) {
    if (!signerSetQualifies(signers)) continue;
    const signerHashes = new Set(signers.map(({response_hash}) => response_hash));
    const remaining = committeeCandidates.filter(({response_hash}) =>
      !signerHashes.has(response_hash));
    for (const additional of combinations(remaining, 2)) {
      const committee = [...signers, ...additional]
        .sort((left, right) => left.response_hash.localeCompare(right.response_hash));
      if (!committeeQualifies(committee)) continue;
      const attestors = externalAttestorSet(attestorCandidates, committee);
      if (!attestors) continue;
      selected = {committee, signers, attestors};
      break selection;
    }
  }
}

let candidatePoolStatus = "INSUFFICIENT_COMMITTEE_CANDIDATES";
if (committeeCandidates.length >= 7 && attestorCandidates.length < 3) {
  candidatePoolStatus = "INDEPENDENCE_ATTESTOR_POOL_INSUFFICIENT";
} else if (committeeCandidates.length >= 7 && !selected) {
  candidatePoolStatus = "CLAIMED_DIVERSITY_OR_ROLE_COVERAGE_INSUFFICIENT";
} else if (selected) {
  candidatePoolStatus = "STRUCTURALLY_READY_FOR_EXTERNAL_ATTESTATION_AND_CERTIFICATE_SIGNING";
}

const selectedHashes = (key) => selected ? selected[key]
  .map(({response_hash}) => response_hash)
  .sort() : [];
const report = {
  schema: "lifepp.external-cai-quorum-readiness.v1",
  evidence_class: "NON_AUTHORITATIVE_STRUCTURAL_READINESS",
  bound_enrollment_request_hash:
    "sha256:af751b72b1a80cdada836f00320e20ac59786eda3240a5ef1a72fe6ea96148c5",
  verified_application_count: applications.length,
  verified_application_signature_count: applications.length,
  committee_candidate_count: committeeCandidates.length,
  independence_attestor_candidate_count: attestorCandidates.length,
  committee_policy: {
    committee_size: 7,
    threshold: 5,
    minimum_control_domains: 3,
    minimum_runtime_domains: 3,
    minimum_ahin_communities: 2,
    required_roles: [...REQUIRED_ROLES],
    minimum_external_attestors: 3,
    minimum_external_attestor_control_domains: 3,
  },
  structural_readiness: {
    candidate_pool_status: candidatePoolStatus,
    structurally_ready: Boolean(selected),
    selected_committee_application_hashes: selectedHashes("committee"),
    selected_signer_application_hashes: selectedHashes("signers"),
    selected_attestor_application_hashes: selectedHashes("attestors"),
    claimed_control_domain_count: selected ? distinctCount(selected.signers, "control_domain_id") : 0,
    claimed_runtime_domain_count: selected ? distinctCount(selected.signers, "runtime_domain_id") : 0,
    claimed_ahin_community_count: selected ? distinctCount(selected.signers, "ahin_community_id") : 0,
    required_role_coverage_claimed: selected ? hasRoleCoverage(selected.signers) : false,
  },
  authority: {
    enrollment_applications_are_certificate_votes: false,
    actual_certificate_signature_count: 0,
    external_quorum_status: "NOT_ESTABLISHED",
    independence_verified: false,
    protocol_authority: false,
    merge_authority: false,
    deployment_authority: false,
    production_finality_claimed: false,
  },
  limitations: [
    "This checker verifies signed enrollment applications and claimed structural diversity only.",
    "Unique declared identifiers do not prove independent control, runtime, provider, community, or economic ownership.",
    "External attestors must still verify control evidence and sign the pinned production registry and member attestations.",
    "Committee members must still sign a canonical autonomous retrospective certificate that passes the private protocol verifier.",
    "This report cannot activate migration, authorize merge or deployment, or establish production finality."
  ],
};
report.readiness_root = sha256(canonical(report));

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
