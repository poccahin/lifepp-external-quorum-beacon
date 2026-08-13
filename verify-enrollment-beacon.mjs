import {createHash, createPublicKey, verify as verifySignature} from "node:crypto";
import {readFileSync} from "node:fs";

const HASH = /^sha256:[a-f0-9]{64}$/;
const BASE64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;
const ENROLLMENT_CLASSES = new Set([
  "COMMITTEE_CANDIDATE",
  "INDEPENDENCE_ATTESTOR_CANDIDATE",
]);
const CAPABILITY_ROLES = new Set([
  "REVIEWER",
  "CHALLENGER",
  "REPLAY",
  "SECURITY",
  "DEPLOYMENT",
  "INDEPENDENCE_ATTESTOR",
]);
const RESPONSE_FIELDS = [
  "protocol_version", "record_type", "request_id",
  "bound_publication_evidence_root", "enrollment_class", "persona_id",
  "github_account_id", "operator_id", "model_provider_id",
  "runtime_domain_id", "control_domain_id", "ahin_community_id",
  "control_nullifier", "lineage_root", "execution_trace_root",
  "ahin_interaction_root", "pocc_status", "pocc_evidence_ref",
  "chainrank_domain_vector_root", "runtime_image_digest", "capability_roles",
  "public_key_pem", "public_key_fingerprint", "independent_evidence_refs",
  "requested_source_access", "declarations", "signed_at", "signature_base64",
  "response_hash",
];
const DECLARATION_FIELDS = [
  "facts_are_independently_supportable", "not_target_author",
  "not_same_runtime_as_target_author", "not_same_operator_as_target_author",
  "no_secret_values_in_response", "application_is_not_a_protocol_vote",
];

const canonical = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};

const sha256 = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

const fingerprint = (pem) => {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("KEY_NOT_ED25519");
  return sha256(key.export({type: "spki", format: "der"}));
};

const hasExactKeys = (value, fields) =>
  value && typeof value === "object" && !Array.isArray(value) &&
  canonical(Object.keys(value).sort()) === canonical([...fields].sort());

const assertText = (value, field) => {
  if (typeof value !== "string" || value.length === 0 || value.includes("REPLACE_")) {
    throw new Error(`INVALID_${field.toUpperCase()}`);
  }
};

const requestPath = new URL("./EXTERNAL_CAI_ENROLLMENT_REQUEST.json", import.meta.url);
const request = JSON.parse(readFileSync(requestPath, "utf8"));
const expectedRequest = structuredClone(request);
delete expectedRequest.request_hash;
const requestHash = sha256(canonical(expectedRequest));
if (request.request_hash !== requestHash) throw new Error("REQUEST_HASH_MISMATCH");
if (request.current_authority.external_quorum_status !== "NOT_ESTABLISHED" ||
    request.current_authority.committee_signature_count !== 0 ||
    request.current_authority.autonomous_merge_authorized !== false ||
    request.current_authority.production_deployment_authorized !== false ||
    request.current_authority.production_finality_claimed !== false) {
  throw new Error("AUTHORITY_ESCALATION");
}

const responsePath = process.argv[2];
if (responsePath) {
  const response = JSON.parse(readFileSync(responsePath, "utf8"));
  if (!hasExactKeys(response, RESPONSE_FIELDS)) throw new Error("RESPONSE_FIELDS_MISMATCH");
  if (response.protocol_version !== request.protocol_version ||
      response.record_type !== "EXTERNAL_CAI_ENROLLMENT_RESPONSE" ||
      response.request_id !== request.request_id ||
      response.bound_publication_evidence_root !== request.bound_publication_evidence_root) {
    throw new Error("RESPONSE_BINDING_MISMATCH");
  }
  if (!ENROLLMENT_CLASSES.has(response.enrollment_class)) {
    throw new Error("INVALID_ENROLLMENT_CLASS");
  }
  for (const field of [
    "persona_id", "github_account_id", "operator_id", "model_provider_id",
    "runtime_domain_id", "control_domain_id", "ahin_community_id",
    "pocc_evidence_ref", "public_key_pem", "signed_at",
  ]) assertText(response[field], field);
  for (const field of [
    "control_nullifier", "lineage_root", "execution_trace_root",
    "ahin_interaction_root", "chainrank_domain_vector_root",
    "runtime_image_digest", "public_key_fingerprint", "response_hash",
  ]) {
    if (!HASH.test(response[field] ?? "")) throw new Error(`INVALID_${field.toUpperCase()}`);
  }
  if (!hasExactKeys(response.declarations, DECLARATION_FIELDS) ||
      DECLARATION_FIELDS.some((field) => response.declarations[field] !== true)) {
    throw new Error("INVALID_DECLARATIONS");
  }
  if (response.requested_source_access !== true ||
      !Array.isArray(response.independent_evidence_refs) ||
      response.independent_evidence_refs.length === 0 ||
      response.independent_evidence_refs.some((ref) =>
        typeof ref !== "string" || ref.length === 0 || ref.includes("REPLACE_"))) {
    throw new Error("INDEPENDENT_EVIDENCE_REQUIRED");
  }
  if (!Array.isArray(response.capability_roles) ||
      response.capability_roles.length === 0 ||
      new Set(response.capability_roles).size !== response.capability_roles.length ||
      response.capability_roles.some((role) => !CAPABILITY_ROLES.has(role))) {
    throw new Error("INVALID_CAPABILITY_ROLES");
  }
  if (response.enrollment_class === "COMMITTEE_CANDIDATE" &&
      (response.pocc_status !== "PASS" ||
       response.capability_roles.every((role) => role === "INDEPENDENCE_ATTESTOR"))) {
    throw new Error("COMMITTEE_CANDIDATE_INELIGIBLE");
  }
  if (response.enrollment_class === "INDEPENDENCE_ATTESTOR_CANDIDATE" &&
      !response.capability_roles.includes("INDEPENDENCE_ATTESTOR")) {
    throw new Error("ATTESTOR_CAPABILITY_REQUIRED");
  }
  const signedAt = Date.parse(response.signed_at);
  if (!Number.isFinite(signedAt) || !/[zZ]|[+-][0-9]{2}:[0-9]{2}$/.test(response.signed_at)) {
    throw new Error("INVALID_SIGNED_AT");
  }
  if (fingerprint(response.public_key_pem) !== response.public_key_fingerprint) {
    throw new Error("PUBLIC_KEY_FINGERPRINT_MISMATCH");
  }
  const complete = structuredClone(response);
  delete complete.response_hash;
  if (response.response_hash !== sha256(canonical(complete))) {
    throw new Error("RESPONSE_HASH_MISMATCH");
  }
  const unsigned = structuredClone(response);
  delete unsigned.signature_base64;
  delete unsigned.response_hash;
  if (!BASE64_SIGNATURE.test(response.signature_base64 ?? "") ||
      !verifySignature(
        null,
        Buffer.from(canonical(unsigned), "utf8"),
        createPublicKey(response.public_key_pem),
        Buffer.from(response.signature_base64, "base64"),
      )) {
    throw new Error("INVALID_RESPONSE_SIGNATURE");
  }
}

console.log(JSON.stringify({
  valid: true,
  request_hash: request.request_hash,
  response_verified: Boolean(responsePath),
  authority_established: false,
}));
