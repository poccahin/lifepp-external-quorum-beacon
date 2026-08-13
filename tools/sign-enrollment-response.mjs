import {execFileSync, spawnSync} from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import {
  closeSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  existsSync,
  writeFileSync,
} from "node:fs";
import {basename, dirname, isAbsolute, join, relative, resolve, sep} from "node:path";
import {tmpdir} from "node:os";
import {fileURLToPath} from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));

const FIELDS = [
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

const canonical = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

const inside = (root, candidate) => {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
};

const gitWorktreeRoot = (cwd) => {
  try {
    return realpathSync(execFileSync(
      "git",
      ["-C", cwd, "rev-parse", "--show-toplevel"],
      {encoding: "utf8", stdio: ["ignore", "pipe", "ignore"]},
    ).trim());
  } catch {
    return null;
  }
};

const parseArgs = (argv) => {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || Object.hasOwn(result, key)) {
      throw new Error("USAGE: --input <json> --private-key <absolute-path> --output <json>");
    }
    result[key] = value;
  }
  const allowed = new Set(["--input", "--private-key", "--output"]);
  if (Object.keys(result).some((key) => !allowed.has(key)) ||
      !result["--input"] || !result["--private-key"] || !result["--output"]) {
    throw new Error("USAGE: --input <json> --private-key <absolute-path> --output <json>");
  }
  return result;
};

const args = parseArgs(process.argv.slice(2));
const inputPath = resolve(args["--input"]);
const privatePath = args["--private-key"];
const outputPath = resolve(args["--output"]);
if (!isAbsolute(privatePath)) throw new Error("PRIVATE_KEY_PATH_MUST_BE_ABSOLUTE");
if (inputPath === outputPath) throw new Error("OUTPUT_MUST_NOT_OVERWRITE_INPUT");
if (!basename(outputPath).endsWith(".json")) throw new Error("OUTPUT_MUST_BE_JSON");
if (existsSync(outputPath)) throw new Error("OUTPUT_ALREADY_EXISTS");

const privateStat = lstatSync(privatePath);
if (!privateStat.isFile() || privateStat.isSymbolicLink()) {
  throw new Error("PRIVATE_KEY_MUST_BE_REGULAR_FILE");
}
const resolvedPrivatePath = realpathSync(privatePath);
const worktreeRoots = [...new Set([
  gitWorktreeRoot(SCRIPT_DIRECTORY),
  gitWorktreeRoot(process.cwd()),
].filter(Boolean))];
if (worktreeRoots.some((worktree) => inside(worktree, resolvedPrivatePath))) {
  throw new Error("PRIVATE_KEY_PATH_MUST_BE_OUTSIDE_GIT_WORKTREE");
}
if (process.platform !== "win32" && (privateStat.mode & 0o077) !== 0) {
  throw new Error("PRIVATE_KEY_PERMISSIONS_MUST_BE_0600_OR_STRICTER");
}

const response = JSON.parse(readFileSync(inputPath, "utf8"));
if (canonical(Object.keys(response).sort()) !== canonical([...FIELDS].sort())) {
  throw new Error("RESPONSE_FIELDS_MISMATCH");
}
const request = JSON.parse(readFileSync(
  resolve(fileURLToPath(new URL("..", import.meta.url)), "EXTERNAL_CAI_ENROLLMENT_REQUEST.json"),
  "utf8",
));
if (response.protocol_version !== request.protocol_version ||
    response.record_type !== "EXTERNAL_CAI_ENROLLMENT_RESPONSE" ||
    response.request_id !== request.request_id ||
    response.bound_publication_evidence_root !== request.bound_publication_evidence_root) {
  throw new Error("RESPONSE_BINDING_MISMATCH");
}
if (typeof response.signed_at !== "string" || response.signed_at.includes("REPLACE_") ||
    !Number.isFinite(Date.parse(response.signed_at)) ||
    !/[zZ]|[+-][0-9]{2}:[0-9]{2}$/.test(response.signed_at)) {
  throw new Error("EXPLICIT_CANONICAL_SIGNED_AT_REQUIRED");
}

const privateKey = createPrivateKey(readFileSync(resolvedPrivatePath, "utf8"));
if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("KEY_NOT_ED25519");
const publicKey = createPublicKey(privateKey);
const publicPem = publicKey.export({type: "spki", format: "pem"});
const fingerprint = sha256(publicKey.export({type: "spki", format: "der"}));
for (const [field, expected] of [
  ["public_key_pem", publicPem],
  ["public_key_fingerprint", fingerprint],
]) {
  const current = response[field];
  if (typeof current === "string" && current.length > 0 && !current.includes("REPLACE_") &&
      current !== expected) {
    throw new Error(`${field.toUpperCase()}_DOES_NOT_MATCH_PRIVATE_KEY`);
  }
  response[field] = expected;
}

response.signature_base64 = "";
response.response_hash = "";
const unsigned = structuredClone(response);
delete unsigned.signature_base64;
delete unsigned.response_hash;
response.signature_base64 = sign(
  null,
  Buffer.from(canonical(unsigned), "utf8"),
  privateKey,
).toString("base64");
const complete = structuredClone(response);
delete complete.response_hash;
response.response_hash = sha256(canonical(complete));

const temporaryDirectory = mkdtempSync(join(tmpdir(), "lifepp-enrollment-sign-"));
const candidatePath = join(temporaryDirectory, "response.json");
writeFileSync(candidatePath, `${JSON.stringify(response, null, 2)}\n`, {mode: 0o600});
const verifierPath = resolve(fileURLToPath(new URL("..", import.meta.url)), "verify-enrollment-beacon.mjs");
let result;
try {
  const verification = spawnSync(process.execPath, [verifierPath, candidatePath], {encoding: "utf8"});
  if (verification.status !== 0) {
    throw new Error(`SIGNED_RESPONSE_FAILED_LOCAL_VERIFICATION:${verification.stderr.trim()}`);
  }
  result = JSON.parse(verification.stdout);
  if (result.valid !== true || result.response_verified !== true ||
      result.authority_established !== false) {
    throw new Error("FAIL_CLOSED_VERIFIER_RESULT");
  }
} finally {
  rmSync(temporaryDirectory, {recursive: true, force: true});
}

const descriptor = openSync(outputPath, "wx", 0o644);
try {
  writeFileSync(descriptor, `${JSON.stringify(response, null, 2)}\n`, {encoding: "utf8"});
} finally {
  closeSync(descriptor);
}

console.log(JSON.stringify({
  valid: true,
  output_path: outputPath,
  persona_id: response.persona_id,
  public_key_fingerprint: fingerprint,
  response_hash: response.response_hash,
  response_verified: true,
  private_key_emitted: false,
  authority_established: false,
}));
