import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import {dirname, join, relative, resolve, sep} from "node:path";

const COMMIT = /^[a-f0-9]{40}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SUBMISSION = /^submissions\/[A-Za-z0-9._-]+\.json$/;
const MAX_OPEN_PULL_REQUESTS = 64;
const MAX_APPLICATION_BYTES = 131072;
const PROJECT_OWNER_DATABASE_ID = "258611371";

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
  const allowed = new Set([
    "--repository",
    "--trusted-base",
    "--remote",
    "--pulls-json",
    "--output-directory",
    "--output-inventory",
  ]);
  if (Object.keys(parsed).some((key) => !allowed.has(key)) ||
      [...allowed].some((key) => !parsed[key])) {
    fail("INVALID_ARGUMENTS", [...allowed].join(" "));
  }
  return parsed;
};

const git = (gitDirectory, args, binary = false) => {
  const result = spawnSync("git", ["--git-dir", gitDirectory, ...args], {
    encoding: binary ? null : "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0 || result.signal !== null || result.error) {
    fail(
      "GIT_INSPECTION_FAILED",
      result.stderr?.toString("utf8").trim() || `git ${args.join(" ")} failed`,
    );
  }
  return result.stdout;
};
const gitExit = (gitDirectory, args) => spawnSync(
  "git",
  ["--git-dir", gitDirectory, ...args],
  {encoding: "utf8", maxBuffer: 1024 * 1024},
);

const inside = (root, candidate) => {
  const rel = relative(root, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`));
};

const args = parseArgs(process.argv.slice(2));
const repository = args["--repository"];
const repositoryOwner = repository.split("/")[0].toLowerCase();
const trustedBase = args["--trusted-base"];
const remote = args["--remote"];
const pullsPath = resolve(args["--pulls-json"]);
const outputDirectory = resolve(args["--output-directory"]);
const outputInventory = resolve(args["--output-inventory"]);

if (!REPOSITORY.test(repository)) fail("INVALID_REPOSITORY", repository);
if (!COMMIT.test(trustedBase)) fail("INVALID_TRUSTED_BASE", trustedBase);
if (!inside(outputDirectory, outputInventory)) {
  fail("OUTPUT_INVENTORY_OUTSIDE_OUTPUT_ROOT", outputInventory);
}

const pulls = JSON.parse(readFileSync(pullsPath, "utf8"));
if (!Array.isArray(pulls) || pulls.length > MAX_OPEN_PULL_REQUESTS) {
  fail("OPEN_PULL_REQUEST_LIMIT_EXCEEDED", `maximum ${MAX_OPEN_PULL_REQUESTS}`);
}
const numbers = pulls.map(({number}) => number);
if (numbers.some((number) => !Number.isSafeInteger(number) || number <= 0) ||
    new Set(numbers).size !== numbers.length) {
  fail("INVALID_PULL_REQUEST_NUMBER_SET", "pull request numbers must be unique positive integers");
}

mkdirSync(outputDirectory, {recursive: false, mode: 0o700});
const repositoryDirectory = join(outputDirectory, "repository.git");
mkdirSync(repositoryDirectory, {mode: 0o700});
const init = spawnSync("git", ["init", "--bare", "--quiet", repositoryDirectory], {
  encoding: "utf8",
});
if (init.status !== 0 || init.signal !== null || init.error) {
  fail("GIT_INIT_FAILED", init.stderr?.trim() || "cannot initialize inspection repository");
}
git(repositoryDirectory, ["fetch", "--no-tags", remote, "refs/heads/main"]);
if (git(repositoryDirectory, ["rev-parse", "FETCH_HEAD"]).trim() !== trustedBase) {
  fail("TRUSTED_BASE_MOVED", "remote main does not match the trusted base");
}

const entries = [];
for (const pull of [...pulls].sort((left, right) => left.number - right.number)) {
  const authorId = pull.user?.id;
  const authorLogin = pull.user?.login;
  const baseCommit = pull.base?.sha;
  const headCommit = pull.head?.sha;
  const headRepository = pull.head?.repo?.full_name;
  const headReference = pull.head?.ref;
  const common = {
    pull_request_number: pull.number,
    author_login: typeof authorLogin === "string" ? authorLogin : null,
    author_database_id: Number.isSafeInteger(authorId) ? String(authorId) : null,
    base_commit: COMMIT.test(baseCommit ?? "") ? baseCommit : null,
    head_commit: COMMIT.test(headCommit ?? "") ? headCommit : null,
    head_repository: typeof headRepository === "string" ? headRepository : null,
    head_reference: typeof headReference === "string" ? headReference : null,
  };
  const rejected = (reason, submissionPath = null) => entries.push({
    ...common,
    preflight_status: "REJECTED",
    preflight_reason: reason,
    submission_path: submissionPath,
    materialized_file: null,
    blob_sha: null,
    blob_size: null,
  });

  if (pull.state !== "open" || typeof pull.draft !== "boolean" ||
      pull.base?.repo?.full_name !== repository || pull.base?.ref !== "main" ||
      !COMMIT.test(baseCommit ?? "") || !COMMIT.test(headCommit ?? "") ||
      !Number.isSafeInteger(authorId) || authorId <= 0 ||
      typeof authorLogin !== "string" || authorLogin.length === 0 ||
      typeof headRepository !== "string" || typeof headReference !== "string") {
    rejected("MALFORMED_OR_DELETED_FORK_PULL_REQUEST");
    continue;
  }

  if (pull.draft) {
    rejected("DRAFT_PULL_REQUEST");
    continue;
  }
  if (String(authorId) === PROJECT_OWNER_DATABASE_ID ||
      authorLogin.toLowerCase() === repositoryOwner ||
      headRepository.toLowerCase() === repository.toLowerCase()) {
    rejected("PROJECT_OWNED_OR_TARGET_AUTHOR_PULL_REQUEST");
    continue;
  }
  if (baseCommit !== trustedBase) {
    rejected("STALE_BASE_COMMIT");
    continue;
  }

  const pullReference = `refs/lifepp/pull/${pull.number}`;
  git(repositoryDirectory, [
    "fetch",
    "--no-tags",
    remote,
    `refs/pull/${pull.number}/head:${pullReference}`,
  ]);
  if (git(repositoryDirectory, ["rev-parse", pullReference]).trim() !== headCommit) {
    fail("PULL_REQUEST_HEAD_MOVED", `pull request ${pull.number}`);
  }
  const ancestry = gitExit(repositoryDirectory, [
    "merge-base",
    "--is-ancestor",
    baseCommit,
    headCommit,
  ]);
  if (ancestry.status === 1 && ancestry.signal === null && !ancestry.error) {
    rejected("HEAD_NOT_DESCENDANT_OF_TRUSTED_BASE");
    continue;
  }
  if (ancestry.status !== 0 || ancestry.signal !== null || ancestry.error) {
    fail("GIT_ANCESTRY_CHECK_FAILED", `pull request ${pull.number}`);
  }

  const rawDiff = git(repositoryDirectory, [
    "diff",
    "--name-status",
    "-z",
    "--no-renames",
    baseCommit,
    headCommit,
    "--",
  ], true);
  const payload = rawDiff.subarray(0, rawDiff.at(-1) === 0 ? -1 : undefined);
  const fields = payload.length === 0 ? [] : payload.toString("utf8").split("\0");
  if (fields.length !== 2) {
    rejected("EXACTLY_ONE_CHANGED_PATH_REQUIRED");
    continue;
  }
  const [changeType, submissionPath] = fields;
  if (changeType !== "A" || !SUBMISSION.test(submissionPath)) {
    rejected("ONE_ADDED_SUBMISSION_JSON_REQUIRED", submissionPath);
    continue;
  }

  const treeLine = git(repositoryDirectory, ["ls-tree", headCommit, "--", submissionPath]).trim();
  const match = /^(\d{6}) blob ([a-f0-9]{40})\t(.+)$/u.exec(treeLine);
  if (!match || match[1] !== "100644" || match[3] !== submissionPath) {
    rejected("SUBMISSION_MUST_BE_REGULAR_NON_EXECUTABLE_BLOB", submissionPath);
    continue;
  }
  const blobSha = match[2];
  const blobSizeText = git(repositoryDirectory, ["cat-file", "-s", blobSha]).trim();
  const blobSize = Number(blobSizeText);
  if (!Number.isSafeInteger(blobSize) || blobSize < 1 || blobSize > MAX_APPLICATION_BYTES) {
    rejected("SUBMISSION_SIZE_OUT_OF_BOUNDS", submissionPath);
    continue;
  }
  const blob = git(repositoryDirectory, ["cat-file", "blob", blobSha], true);
  if (blob.length !== blobSize) fail("BLOB_SIZE_MISMATCH", submissionPath);
  const materializedFile = `inputs/pr-${pull.number}.json`;
  const destination = join(outputDirectory, materializedFile);
  mkdirSync(dirname(destination), {recursive: true, mode: 0o700});
  const descriptor = openSync(destination, "wx", 0o600);
  try {
    writeFileSync(descriptor, blob);
  } finally {
    closeSync(descriptor);
  }
  entries.push({
    ...common,
    preflight_status: "CANDIDATE",
    preflight_reason: null,
    submission_path: submissionPath,
    materialized_file: materializedFile,
    blob_sha: blobSha,
    blob_size: blobSize,
  });
}

const inventory = {
  schema: "lifepp.external-cai-open-pr-inventory.v1",
  evidence_class: "NON_AUTHORITATIVE_TRANSPORT_INVENTORY",
  repository,
  trusted_base_commit: trustedBase,
  open_pull_request_count: pulls.length,
  entries,
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
};
inventory.inventory_root = sha256(canonical(inventory));
const serialized = `${JSON.stringify(inventory, null, 2)}\n`;
const inventoryDescriptor = openSync(outputInventory, "wx", 0o600);
try {
  writeFileSync(inventoryDescriptor, serialized, {encoding: "utf8"});
} finally {
  closeSync(inventoryDescriptor);
}
process.stdout.write(serialized);
