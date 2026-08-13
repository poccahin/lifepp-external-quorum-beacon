import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {
  cpSync,
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {dirname, join, resolve} from "node:path";
import {tmpdir} from "node:os";
import {fileURLToPath} from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIRECTORY, "..");
const GENERATOR = join(ROOT, "tools/generate-ed25519-keypair.mjs");
const SIGNER = join(ROOT, "tools/sign-enrollment-response.mjs");
const CHECKER = join(ROOT, "tools/check-quorum-readiness.mjs");
const REQUEST = JSON.parse(readFileSync(join(ROOT, "EXTERNAL_CAI_ENROLLMENT_REQUEST.json"), "utf8"));
const TEMPLATE = JSON.parse(readFileSync(
  join(ROOT, "EXTERNAL_CAI_ENROLLMENT_RESPONSE.template.json"),
  "utf8",
));
const WORK = mkdtempSync(join(tmpdir(), "lifepp-quorum-readiness-test-"));

const hash = (label) =>
  `sha256:${createHash("sha256").update(label).digest("hex")}`;

const run = (script, args, expected = 0) => {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== expected || result.signal !== null || result.error) {
    throw new Error(JSON.stringify({script, args, expected, result}, null, 2));
  }
  return result;
};

const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

const makeApplication = (index, enrollmentClass, role, overrides = {}) => {
  const privateKey = join(WORK, `private-${index}.pem`);
  const publicKey = join(WORK, `public-${index}.pem`);
  run(GENERATOR, ["--private-key", privateKey, "--public-key", publicKey]);
  chmodSync(privateKey, 0o600);

  const response = structuredClone(TEMPLATE);
  Object.assign(response, {
    protocol_version: REQUEST.protocol_version,
    request_id: REQUEST.request_id,
    bound_publication_evidence_root: REQUEST.bound_publication_evidence_root,
    enrollment_class: enrollmentClass,
    persona_id: `external-test-persona-${index}`,
    github_account_id: `github-${index}`,
    operator_id: `operator-${index}`,
    model_provider_id: `provider-${index}`,
    runtime_domain_id: `runtime-${index % 3}`,
    control_domain_id: enrollmentClass === "COMMITTEE_CANDIDATE"
      ? `committee-control-${index % 3}`
      : `attestor-control-${index}`,
    ahin_community_id: `community-${index % 2}`,
    control_nullifier: hash(`control-nullifier-${index}`),
    lineage_root: hash(`lineage-${index}`),
    execution_trace_root: hash(`execution-${index}`),
    ahin_interaction_root: hash(`ahin-${index}`),
    pocc_status: "PASS",
    pocc_evidence_ref: `https://example.invalid/evidence/pocc-${index}`,
    chainrank_domain_vector_root: hash(`chainrank-${index}`),
    runtime_image_digest: hash(`runtime-image-${index}`),
    capability_roles: [role],
    independent_evidence_refs: [`https://example.invalid/evidence/independence-${index}`],
    requested_source_access: true,
    signed_at: `2026-08-14T04:${String(index).padStart(2, "0")}:00+08:00`,
    ...overrides,
  });
  const prepared = join(WORK, `prepared-${index}.json`);
  const signed = join(WORK, `signed-${index}.json`);
  writeFileSync(prepared, `${JSON.stringify(response, null, 2)}\n`, {mode: 0o600});
  run(SIGNER, ["--input", prepared, "--private-key", privateKey, "--output", signed]);
  return signed;
};

try {
  const zeroFirst = run(CHECKER, []).stdout;
  const zeroSecond = run(CHECKER, []).stdout;
  expect(zeroFirst === zeroSecond, "zero-input report is not deterministic");
  const zero = JSON.parse(zeroFirst);
  expect(zero.structural_readiness.structurally_ready === false, "zero input became ready");
  expect(zero.authority.protocol_authority === false, "zero input gained authority");

  const roles = ["REVIEWER", "CHALLENGER", "REPLAY", "SECURITY", "REVIEWER", "REPLAY", "SECURITY"];
  const committee = roles.map((role, index) =>
    makeApplication(index, "COMMITTEE_CANDIDATE", role));
  const attestors = [7, 8, 9].map((index) =>
    makeApplication(index, "INDEPENDENCE_ATTESTOR_CANDIDATE", "INDEPENDENCE_ATTESTOR"));
  const all = [...committee, ...attestors];

  const first = run(CHECKER, all).stdout;
  const second = run(CHECKER, all).stdout;
  const reversed = run(CHECKER, [...all].reverse()).stdout;
  expect(first === second, "identical aggregate input is not byte-identical");
  expect(first === reversed, "input order changes aggregate output");
  const ready = JSON.parse(first);
  expect(ready.structural_readiness.structurally_ready === true, "eligible structural set not found");
  expect(
    ready.structural_readiness.candidate_pool_status ===
      "STRUCTURALLY_READY_FOR_EXTERNAL_ATTESTATION_AND_CERTIFICATE_SIGNING",
    "unexpected structural readiness status",
  );
  expect(ready.verified_application_signature_count === 10, "application signature count mismatch");
  expect(ready.authority.enrollment_applications_are_certificate_votes === false,
    "applications became votes");
  expect(ready.authority.actual_certificate_signature_count === 0,
    "certificate signatures were fabricated");
  expect(ready.authority.external_quorum_status === "NOT_ESTABLISHED",
    "external quorum was fabricated");
  expect(ready.authority.independence_verified === false,
    "independence was fabricated");
  expect(ready.authority.protocol_authority === false, "protocol authority was fabricated");
  expect(ready.authority.merge_authority === false, "merge authority was fabricated");
  expect(ready.authority.deployment_authority === false, "deployment authority was fabricated");

  const noAttestors = JSON.parse(run(CHECKER, committee).stdout);
  expect(
    noAttestors.structural_readiness.candidate_pool_status ===
      "INDEPENDENCE_ATTESTOR_POOL_INSUFFICIENT",
    "missing attestors did not fail closed",
  );
  expect(noAttestors.authority.protocol_authority === false,
    "missing attestors gained authority");

  const concentratedCommittee = roles.map((role, offset) =>
    makeApplication(10 + offset, "COMMITTEE_CANDIDATE", role, {
      operator_id: "one-controlling-operator",
    }));
  const concentrated = JSON.parse(run(
    CHECKER,
    [...concentratedCommittee, ...attestors],
  ).stdout);
  expect(concentrated.structural_readiness.structurally_ready === false,
    "one operator controlling seven personas became structurally ready");
  expect(
    concentrated.structural_readiness.candidate_pool_status ===
      "CLAIMED_DIVERSITY_OR_ROLE_COVERAGE_INSUFFICIENT",
    "operator concentration did not fail closed",
  );
  expect(concentrated.authority.protocol_authority === false,
    "operator concentration gained authority");

  const duplicate = run(CHECKER, [committee[0], committee[0]], 1);
  expect(duplicate.stderr.includes("DUPLICATE_APPLICATION_IDENTITY"),
    "duplicate identity was not rejected");

  const unsigned = join(WORK, "unsigned.json");
  writeFileSync(unsigned, `${JSON.stringify(TEMPLATE, null, 2)}\n`, {mode: 0o600});
  const invalid = run(CHECKER, [unsigned], 1);
  expect(invalid.stderr.includes("APPLICATION_INTEGRITY_VERIFICATION_FAILED"),
    "unsigned application was not rejected");

  const overLimit = run(CHECKER, Array.from({length: 17}, () => committee[0]), 1);
  expect(overLimit.stderr.includes("TOO_MANY_APPLICATIONS"),
    "application cap was not enforced");

  const tamperedRoot = join(WORK, "tampered-verifier");
  const tamperedTools = join(tamperedRoot, "tools");
  mkdirSync(tamperedTools, {recursive: true});
  cpSync(CHECKER, join(tamperedTools, "check-quorum-readiness.mjs"));
  writeFileSync(
    join(tamperedRoot, "verify-enrollment-beacon.mjs"),
    `${readFileSync(join(ROOT, "verify-enrollment-beacon.mjs"), "utf8")}\n// tampered\n`,
  );
  const tampered = run(join(tamperedTools, "check-quorum-readiness.mjs"), [], 1);
  expect(tampered.stderr.includes("PINNED_VERIFIER_MISMATCH"),
    "tampered single-application verifier was not rejected");

  process.stdout.write(`${JSON.stringify({
    schema: "lifepp.external-cai-quorum-readiness-checker-test.v1",
    zero_input_deterministic: true,
    valid_application_signatures_verified: 10,
    input_order_independent: true,
    structural_readiness_detected: true,
    structural_readiness_is_authority: false,
    actual_certificate_signature_count: 0,
    external_quorum_status: "NOT_ESTABLISHED",
    independence_verified: false,
    duplicate_identity_rejected: true,
    unsigned_application_rejected: true,
    missing_attestors_fail_closed: true,
    operator_quorum_concentration_rejected: true,
    bounded_application_count: 16,
    tampered_pinned_verifier_rejected: true,
    authority_established: false,
  }, null, 2)}\n`);
} finally {
  rmSync(WORK, {recursive: true, force: true});
}
