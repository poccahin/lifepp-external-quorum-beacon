import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIRECTORY, "..");
const MATERIALIZER = join(ROOT, "tools/materialize-open-enrollment-prs.mjs");
const BUILDER = join(ROOT, "tools/build-open-enrollment-readiness.mjs");
const GENERATOR = join(ROOT, "tools/generate-ed25519-keypair.mjs");
const SIGNER = join(ROOT, "tools/sign-enrollment-response.mjs");
const REQUEST = JSON.parse(readFileSync(join(ROOT, "EXTERNAL_CAI_ENROLLMENT_REQUEST.json")));
const TEMPLATE = JSON.parse(readFileSync(
  join(ROOT, "EXTERNAL_CAI_ENROLLMENT_RESPONSE.template.json"),
));
const WORK = mkdtempSync(join(tmpdir(), "lifepp-open-enrollment-collector-test-"));
const REMOTE = join(WORK, "remote.git");
const REPOSITORY = join(WORK, "repository");
const REPOSITORY_NAME = "poccahin/lifepp-external-quorum-beacon";

const hash = (label) =>
  `sha256:${createHash("sha256").update(label).digest("hex")}`;
const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? ROOT,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  const expected = options.expected ?? 0;
  if (result.status !== expected || result.signal !== null || result.error) {
    throw new Error(JSON.stringify({command, args, expected, result}, null, 2));
  }
  return result;
};
const git = (cwd, args) => run("git", args, {cwd}).stdout.trim();
const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

const makeApplication = (index, enrollmentClass, role, overrides = {}) => {
  const privateKey = join(WORK, `private-${index}.pem`);
  const publicKey = join(WORK, `public-${index}.pem`);
  run(process.execPath, [
    GENERATOR,
    "--private-key", privateKey,
    "--public-key", publicKey,
  ]);
  chmodSync(privateKey, 0o600);
  const response = structuredClone(TEMPLATE);
  Object.assign(response, {
    protocol_version: REQUEST.protocol_version,
    request_id: REQUEST.request_id,
    bound_publication_evidence_root: REQUEST.bound_publication_evidence_root,
    enrollment_class: enrollmentClass,
    persona_id: `external-persona-${index}`,
    github_account_id: String(1000 + index),
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
    pocc_evidence_ref: `https://example.invalid/pocc/${index}`,
    chainrank_domain_vector_root: hash(`chainrank-${index}`),
    runtime_image_digest: hash(`runtime-image-${index}`),
    capability_roles: [role],
    independent_evidence_refs: [`https://example.invalid/independence/${index}`],
    requested_source_access: true,
    signed_at: `2026-08-14T05:${String(index).padStart(2, "0")}:00+08:00`,
    ...overrides,
  });
  const prepared = join(WORK, `prepared-${index}.json`);
  const signed = join(WORK, `signed-${index}.json`);
  writeFileSync(prepared, `${JSON.stringify(response, null, 2)}\n`, {mode: 0o600});
  run(process.execPath, [
    SIGNER,
    "--input", prepared,
    "--private-key", privateKey,
    "--output", signed,
  ]);
  return {signed, response: JSON.parse(readFileSync(signed, "utf8"))};
};

const pullMetadata = ({number, base, head, authorId, authorLogin, draft = false}) => ({
  number,
  state: "open",
  draft,
  user: {id: authorId, login: authorLogin},
  base: {
    sha: base,
    ref: "main",
    repo: {full_name: REPOSITORY_NAME},
  },
  head: {
    sha: head,
    ref: `enrollment-${number}`,
    repo: {full_name: `${authorLogin}/lifepp-external-quorum-beacon`},
  },
});

const publishPull = ({number, base, application, extraFile = false}) => {
  git(REPOSITORY, ["checkout", "--detach", "--force", base]);
  mkdirSync(join(REPOSITORY, "submissions"), {recursive: true});
  const target = join(REPOSITORY, "submissions", `${application.response.persona_id}.json`);
  copyFileSync(application.signed, target);
  git(REPOSITORY, ["add", relativePath(target)]);
  if (extraFile) {
    writeFileSync(join(REPOSITORY, "unexpected.txt"), "not allowed\n");
    git(REPOSITORY, ["add", "unexpected.txt"]);
  }
  git(REPOSITORY, ["commit", "-m", `test enrollment ${number}`]);
  const head = git(REPOSITORY, ["rev-parse", "HEAD"]);
  git(REPOSITORY, ["push", "origin", `HEAD:refs/pull/${number}/head`]);
  return head;
};
const relativePath = (target) => target.slice(`${REPOSITORY}/`.length);

const collect = (pulls, label) => {
  const output = join(WORK, label);
  const pullsPath = join(WORK, `${label}-pulls.json`);
  const inventory = join(output, "inventory.json");
  const report = join(output, "readiness.json");
  writeFileSync(pullsPath, `${JSON.stringify(pulls, null, 2)}\n`);
  run(process.execPath, [
    MATERIALIZER,
    "--repository", REPOSITORY_NAME,
    "--trusted-base", base,
    "--remote", REMOTE,
    "--pulls-json", pullsPath,
    "--output-directory", output,
    "--output-inventory", inventory,
  ]);
  run(process.execPath, [
    BUILDER,
    "--inventory", inventory,
    "--output", report,
  ]);
  return {
    inventory,
    report,
    inventoryBytes: readFileSync(inventory),
    reportBytes: readFileSync(report),
    reportJson: JSON.parse(readFileSync(report, "utf8")),
  };
};

let base;
try {
  run("git", ["init", "--bare", "--quiet", REMOTE]);
  mkdirSync(REPOSITORY);
  run("git", ["init", "--initial-branch=main", "--quiet"], {cwd: REPOSITORY});
  git(REPOSITORY, ["config", "user.name", "LifePP collector test"]);
  git(REPOSITORY, ["config", "user.email", "collector-test@lifepp.invalid"]);
  writeFileSync(join(REPOSITORY, "README.md"), "trusted base\n");
  git(REPOSITORY, ["add", "README.md"]);
  git(REPOSITORY, ["commit", "-m", "trusted base"]);
  base = git(REPOSITORY, ["rev-parse", "HEAD"]);
  git(REPOSITORY, ["remote", "add", "origin", REMOTE]);
  git(REPOSITORY, ["push", "origin", "main"]);

  const roles = [
    "REVIEWER",
    "CHALLENGER",
    "REPLAY",
    "SECURITY",
    "REVIEWER",
    "REPLAY",
    "SECURITY",
  ];
  const pulls = [];
  const applications = [];
  for (let index = 0; index < 10; index += 1) {
    const enrollmentClass = index < 7
      ? "COMMITTEE_CANDIDATE"
      : "INDEPENDENCE_ATTESTOR_CANDIDATE";
    const role = index < 7 ? roles[index] : "INDEPENDENCE_ATTESTOR";
    const application = makeApplication(index, enrollmentClass, role);
    applications.push(application);
    const number = index + 1;
    const head = publishPull({number, base, application});
    pulls.push(pullMetadata({
      number,
      base,
      head,
      authorId: 1000 + index,
      authorLogin: `external-${index}`,
    }));
  }

  const accountMismatch = makeApplication(
    10,
    "COMMITTEE_CANDIDATE",
    "REVIEWER",
    {github_account_id: "999999"},
  );
  const mismatchHead = publishPull({number: 11, base, application: accountMismatch});
  pulls.push(pullMetadata({
    number: 11,
    base,
    head: mismatchHead,
    authorId: 1010,
    authorLogin: "external-10",
  }));

  const extraApplication = makeApplication(11, "COMMITTEE_CANDIDATE", "SECURITY");
  const extraHead = publishPull({
    number: 12,
    base,
    application: extraApplication,
    extraFile: true,
  });
  pulls.push(pullMetadata({
    number: 12,
    base,
    head: extraHead,
    authorId: 1011,
    authorLogin: "external-11",
  }));
  pulls.push(pullMetadata({
    number: 13,
    base,
    head: base,
    authorId: 1012,
    authorLogin: "external-12",
    draft: true,
  }));
  pulls.push(pullMetadata({
    number: 15,
    base,
    head: pulls[0].head.sha,
    authorId: 9000,
    authorLogin: "poccahin",
  }));
  pulls.at(-1).head.repo.full_name = REPOSITORY_NAME;
  const malformed = pullMetadata({
    number: 16,
    base,
    head: pulls[0].head.sha,
    authorId: 9016,
    authorLogin: "deleted-fork-owner",
  });
  malformed.head.repo = null;
  pulls.push(malformed);
  const unrelatedTree = git(REPOSITORY, ["rev-parse", `${pulls[0].head.sha}^{tree}`]);
  const unrelatedHead = git(REPOSITORY, ["commit-tree", unrelatedTree, "-m", "unrelated head"]);
  git(REPOSITORY, ["push", "origin", `${unrelatedHead}:refs/pull/18/head`]);
  pulls.push(pullMetadata({
    number: 18,
    base,
    head: unrelatedHead,
    authorId: 1000,
    authorLogin: "external-0",
  }));

  const first = collect(pulls, "first");
  const second = collect([...pulls].reverse(), "second");
  expect(first.inventoryBytes.equals(second.inventoryBytes),
    "PR input ordering changed inventory bytes");
  expect(first.reportBytes.equals(second.reportBytes),
    "PR input ordering changed readiness bytes");
  expect(first.reportJson.verified_application_count === 10,
    "ten valid signed applications were not retained");
  expect(first.reportJson.rejected_application_count === 6,
    "negative-control rejection count mismatch");
  expect(first.reportJson.aggregate_readiness.structural_readiness.structurally_ready === true,
    "valid 7+3 structural candidate set was not detected");
  expect(first.reportJson.authority.actual_certificate_signature_count === 0,
    "collector fabricated certificate signatures");
  expect(first.reportJson.authority.external_quorum_status === "NOT_ESTABLISHED",
    "collector fabricated external quorum");
  expect(first.reportJson.authority.independence_verified === false,
    "collector fabricated independence");
  const reasons = new Set(first.reportJson.rejected_applications.map(({reason}) => reason));
  for (const reason of [
    "GITHUB_ACCOUNT_BINDING_MISMATCH",
    "EXACTLY_ONE_CHANGED_PATH_REQUIRED",
    "DRAFT_PULL_REQUEST",
    "PROJECT_OWNED_OR_TARGET_AUTHOR_PULL_REQUEST",
    "MALFORMED_OR_DELETED_FORK_PULL_REQUEST",
    "HEAD_NOT_DESCENDANT_OF_TRUSTED_BASE",
  ]) {
    expect(reasons.has(reason), `${reason} negative control was not rejected`);
  }

  git(REPOSITORY, ["push", "origin", `${pulls[0].head.sha}:refs/pull/14/head`]);
  const duplicatePull = pullMetadata({
    number: 14,
    base,
    head: pulls[0].head.sha,
    authorId: 1000,
    authorLogin: "external-0",
  });
  const duplicate = collect([...pulls.slice(0, 10), duplicatePull], "duplicate");
  expect(duplicate.reportJson.rejected_applications.filter(({reason}) =>
    reason === "DUPLICATE_RESPONSE_HASH").length === 2,
  "duplicate response hashes did not reject both applications");
  expect(duplicate.reportJson.authority.protocol_authority === false,
    "duplicate applications gained authority");

  const sameAuthorApplication = makeApplication(
    17,
    "COMMITTEE_CANDIDATE",
    "REVIEWER",
    {github_account_id: "1000"},
  );
  const sameAuthorHead = publishPull({
    number: 17,
    base,
    application: sameAuthorApplication,
  });
  const sameAuthor = collect([
    ...pulls.slice(0, 10),
    pullMetadata({
      number: 17,
      base,
      head: sameAuthorHead,
      authorId: 1000,
      authorLogin: "renamed-external-0",
    }),
  ], "same-author");
  expect(sameAuthor.reportJson.rejected_applications.filter(({reason}) =>
    reason === "DUPLICATE_AUTHOR_DATABASE_ID").length === 2,
  "one immutable GitHub account occupied multiple applications");
  expect(sameAuthor.reportJson.authority.protocol_authority === false,
    "same-author applications gained authority");

  const tamperedDirectory = join(WORK, "tampered");
  mkdirSync(tamperedDirectory);
  const tamperedInventory = JSON.parse(first.inventoryBytes.toString("utf8"));
  tamperedInventory.open_pull_request_count += 1;
  const tamperedInventoryPath = join(tamperedDirectory, "inventory.json");
  const tamperedOutput = join(tamperedDirectory, "readiness.json");
  writeFileSync(tamperedInventoryPath, `${JSON.stringify(tamperedInventory, null, 2)}\n`);
  const tampered = run(process.execPath, [
    BUILDER,
    "--inventory", tamperedInventoryPath,
    "--output", tamperedOutput,
  ], {expected: 1});
  expect(tampered.stderr.includes("INVENTORY_ROOT_MISMATCH"),
    "tampered inventory root was not rejected");

  process.stdout.write(`${JSON.stringify({
    schema: "lifepp.external-cai-open-pr-collector-test.v1",
    trusted_git_object_inspection: true,
    verified_application_count: 10,
    structural_candidate_set_detected: true,
    github_author_database_id_bound: true,
    pull_request_input_order_independent: true,
    duplicate_response_rejected: true,
    duplicate_github_author_rejected: true,
    draft_pull_request_rejected: true,
    multi_path_pull_request_rejected: true,
    project_owned_pull_request_rejected: true,
    deleted_fork_pull_request_rejected: true,
    unrelated_history_rejected: true,
    tampered_inventory_rejected: true,
    actual_certificate_signature_count: 0,
    external_quorum_status: "NOT_ESTABLISHED",
    independence_verified: false,
    authority_established: false,
  }, null, 2)}\n`);
} finally {
  rmSync(WORK, {recursive: true, force: true});
}
