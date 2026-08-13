import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {closeSync, lstatSync, openSync, readFileSync, writeFileSync} from "node:fs";
import {dirname, isAbsolute, relative, resolve, sep} from "node:path";
import {fileURLToPath} from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIRECTORY, "..");
const VERIFIER = resolve(ROOT, "verify-enrollment-beacon.mjs");
const CHECKER = resolve(ROOT, "tools/check-quorum-readiness.mjs");
const PINNED_VERIFIER_SHA256 =
  "ba751fbd9664852f30647668f5e5ff03d189a992b47775e60273c7411f814b44";
const PINNED_CHECKER_SHA256 =
  "4c0c04679f0d7da3b5cd16256cac0013665976acc3a44a236a8acff8cea6eeab";
const HASH = /^sha256:[a-f0-9]{64}$/;
const PERSONA = /^[A-Za-z0-9._-]+$/;
const MAX_VERIFIED_APPLICATIONS = 16;
const UNIQUE_FIELDS = [
  "response_hash",
  "persona_id",
  "public_key_fingerprint",
  "control_nullifier",
];
const UNIQUE_TRANSPORT_FIELDS = ["author_database_id"];
const SAFE_AUTHORITY = Object.freeze({
  enrollment_applications_are_certificate_votes: false,
  actual_certificate_signature_count: 0,
  external_quorum_status: "NOT_ESTABLISHED",
  independence_verified: false,
  protocol_authority: false,
  merge_authority: false,
  deployment_authority: false,
  production_finality_claimed: false,
});

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
const fileSha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const inside = (root, candidate) => {
  const rel = relative(root, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`));
};
const authorityIsSafe = (value) => canonical(value) === canonical(SAFE_AUTHORITY);
const parseArgs = (argv) => {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || Object.hasOwn(parsed, key)) {
      fail("INVALID_ARGUMENTS", "arguments must be unique --name value pairs");
    }
    parsed[key] = value;
  }
  if (Object.keys(parsed).some((key) => !["--inventory", "--output"].includes(key)) ||
      !parsed["--inventory"] || !parsed["--output"]) {
    fail("INVALID_ARGUMENTS", "--inventory <json> --output <json>");
  }
  return parsed;
};

if (fileSha256(VERIFIER) !== PINNED_VERIFIER_SHA256) {
  fail("PINNED_VERIFIER_MISMATCH", "single-application verifier bytes changed");
}
if (fileSha256(CHECKER) !== PINNED_CHECKER_SHA256) {
  fail("PINNED_CHECKER_MISMATCH", "aggregate readiness checker bytes changed");
}

const args = parseArgs(process.argv.slice(2));
const inventoryPath = resolve(args["--inventory"]);
const outputPath = resolve(args["--output"]);
const inventoryDirectory = dirname(inventoryPath);
const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
if (inventory.schema !== "lifepp.external-cai-open-pr-inventory.v1" ||
    inventory.evidence_class !== "NON_AUTHORITATIVE_TRANSPORT_INVENTORY" ||
    !Array.isArray(inventory.entries) || !HASH.test(inventory.inventory_root ?? "")) {
  fail("INVALID_INVENTORY", "inventory schema or root is invalid");
}
const inventoryBody = structuredClone(inventory);
delete inventoryBody.inventory_root;
if (sha256(canonical(inventoryBody)) !== inventory.inventory_root) {
  fail("INVENTORY_ROOT_MISMATCH", "inventory changed after materialization");
}
if (!authorityIsSafe(inventory.authority)) {
  fail("INVENTORY_AUTHORITY_ESCALATION", "inventory must remain non-authoritative");
}

const verified = [];
const rejected = [];
const reject = (entry, reason) => rejected.push({
  pull_request_number: entry.pull_request_number,
  head_commit: entry.head_commit,
  author_login: entry.author_login,
  author_database_id: entry.author_database_id,
  submission_path: entry.submission_path,
  reason,
});

for (const entry of inventory.entries) {
  if (entry.preflight_status !== "CANDIDATE") {
    reject(entry, entry.preflight_reason ?? "PREFLIGHT_REJECTED");
    continue;
  }
  try {
    if (isAbsolute(entry.materialized_file ?? "")) {
      throw new Error("MATERIALIZED_PATH_MUST_BE_RELATIVE");
    }
    const applicationPath = resolve(inventoryDirectory, entry.materialized_file);
    if (!inside(inventoryDirectory, applicationPath)) {
      throw new Error("MATERIALIZED_PATH_ESCAPES_INVENTORY");
    }
    const stat = lstatSync(applicationPath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("APPLICATION_NOT_REGULAR_FILE");
    const result = spawnSync(process.execPath, [VERIFIER, applicationPath], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });
    if (result.status !== 0 || result.signal !== null || result.error) {
      throw new Error("APPLICATION_SIGNATURE_OR_BINDING_INVALID");
    }
    const verification = JSON.parse(result.stdout);
    if (verification.valid !== true || verification.response_verified !== true ||
        verification.authority_established !== false) {
      throw new Error("FAIL_CLOSED_APPLICATION_RESULT");
    }
    const application = JSON.parse(readFileSync(applicationPath, "utf8"));
    if (application.github_account_id !== entry.author_database_id) {
      throw new Error("GITHUB_ACCOUNT_BINDING_MISMATCH");
    }
    if (!PERSONA.test(application.persona_id ?? "") ||
        entry.submission_path !== `submissions/${application.persona_id}.json`) {
      throw new Error("PERSONA_PATH_BINDING_MISMATCH");
    }
    verified.push({entry, application, applicationPath});
  } catch (error) {
    reject(entry, /^[A-Z0-9_]+$/u.test(error.message) ? error.message : "APPLICATION_REJECTED");
  }
}

const duplicates = new Set();
for (const field of UNIQUE_FIELDS) {
  const counts = new Map();
  for (const candidate of verified) {
    const value = candidate.application[field];
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  for (const [value, count] of counts) {
    if (count > 1) duplicates.add(`${field}\0${value}`);
  }
}
for (const field of UNIQUE_TRANSPORT_FIELDS) {
  const counts = new Map();
  for (const candidate of verified) {
    const value = candidate.entry[field];
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  for (const [value, count] of counts) {
    if (count > 1) duplicates.add(`${field}\0${value}`);
  }
}
const eligible = [];
for (const candidate of verified) {
  const duplicateField = UNIQUE_FIELDS.find((field) =>
    duplicates.has(`${field}\0${candidate.application[field]}`));
  const duplicateTransportField = UNIQUE_TRANSPORT_FIELDS.find((field) =>
    duplicates.has(`${field}\0${candidate.entry[field]}`));
  if (duplicateField || duplicateTransportField) {
    reject(
      candidate.entry,
      `DUPLICATE_${(duplicateField ?? duplicateTransportField).toUpperCase()}`,
    );
  } else {
    eligible.push(candidate);
  }
}
eligible.sort((left, right) =>
  left.application.response_hash.localeCompare(right.application.response_hash));
rejected.sort((left, right) => left.pull_request_number - right.pull_request_number ||
  left.reason.localeCompare(right.reason));

let aggregateStatus = "CHECKED";
let readiness = null;
if (eligible.length > MAX_VERIFIED_APPLICATIONS) {
  aggregateStatus = "VERIFIED_APPLICATION_LIMIT_EXCEEDED";
} else {
  const check = spawnSync(
    process.execPath,
    [CHECKER, ...eligible.map(({applicationPath}) => applicationPath)],
    {encoding: "utf8", maxBuffer: 8 * 1024 * 1024},
  );
  if (check.status !== 0 || check.signal !== null || check.error) {
    fail("AGGREGATE_READINESS_CHECK_FAILED", check.stderr.trim() || "checker failed");
  }
  readiness = JSON.parse(check.stdout);
  if (readiness.authority?.actual_certificate_signature_count !== 0 ||
      readiness.authority?.external_quorum_status !== "NOT_ESTABLISHED" ||
      readiness.authority?.independence_verified !== false ||
      readiness.authority?.protocol_authority !== false ||
      readiness.authority?.merge_authority !== false ||
      readiness.authority?.deployment_authority !== false ||
      readiness.authority?.production_finality_claimed !== false) {
    fail("AGGREGATE_AUTHORITY_ESCALATION", "checker emitted authority");
  }
}

const report = {
  schema: "lifepp.external-cai-open-pr-readiness.v1",
  evidence_class: "NON_AUTHORITATIVE_TRANSPORT_READINESS",
  repository: inventory.repository,
  trusted_base_commit: inventory.trusted_base_commit,
  source_inventory_root: inventory.inventory_root,
  open_pull_request_count: inventory.open_pull_request_count,
  verified_application_count: eligible.length,
  rejected_application_count: rejected.length,
  aggregate_status: aggregateStatus,
  verified_application_bindings: eligible.map(({entry, application}) => ({
    pull_request_number: entry.pull_request_number,
    head_commit: entry.head_commit,
    author_login: entry.author_login,
    author_database_id: entry.author_database_id,
    submission_path: entry.submission_path,
    persona_id: application.persona_id,
    enrollment_class: application.enrollment_class,
    response_hash: application.response_hash,
    public_key_fingerprint: application.public_key_fingerprint,
    control_nullifier: application.control_nullifier,
  })),
  rejected_applications: rejected,
  aggregate_readiness: readiness,
  authority: {...SAFE_AUTHORITY},
  limitations: [
    "A GitHub account binding proves submission provenance, not control independence.",
    "Open pull request applications are not committee seats, attestor admissions, or certificate votes.",
    "External attestors must still verify control evidence and the protocol verifier must accept real certificate signatures.",
    "This report cannot activate migration, authorize merge or deployment, or establish production finality."
  ],
};
report.snapshot_root = sha256(canonical(report));
const serialized = `${JSON.stringify(report, null, 2)}\n`;
const outputDescriptor = openSync(outputPath, "wx", 0o600);
try {
  writeFileSync(outputDescriptor, serialized, {encoding: "utf8"});
} finally {
  closeSync(outputDescriptor);
}
process.stdout.write(serialized);
