import {readFileSync} from "node:fs";
import {dirname, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workflowPath = resolve(
  ROOT,
  ".github/workflows/aggregate-open-enrollment-readiness.yml",
);
const workflow = readFileSync(workflowPath, "utf8");
const individualWorkflow = readFileSync(resolve(
  ROOT,
  ".github/workflows/verify-external-cai-enrollment.yml",
), "utf8");
const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

expect(workflow.includes("pull_request_target:"), "trusted-base PR trigger missing");
expect(workflow.includes("workflow_dispatch:"), "manual refresh trigger missing");
expect(workflow.includes("schedule:"), "scheduled refresh trigger missing");
expect(
  workflow.includes("permissions:\n  contents: read\n  pull-requests: read"),
  "workflow permissions are not explicitly read-only",
);
expect(!/^\s+[A-Za-z-]+:\s+write\s*$/mu.test(workflow), "write permission present");
expect(!workflow.includes("actions/checkout"), "workflow must not checkout applicant code");
expect(!/\bgit\s+push\b/u.test(workflow), "workflow must not push Git refs");
expect(!/\bgh\s+(pr|api|issue)\b/u.test(workflow), "workflow must not mutate via gh");
expect(!/--request\s+(POST|PUT|PATCH|DELETE)/u.test(workflow), "mutating HTTP request present");
expect(workflow.includes("refs/heads/main"), "trusted main fetch missing");
expect(workflow.includes("TRUSTED_BASE_SHA"), "trusted SHA binding missing");
expect(workflow.includes("materialize-open-enrollment-prs.mjs"), "materializer missing");
expect(workflow.includes("build-open-enrollment-readiness.mjs"), "builder missing");
expect(workflow.includes("test-open-enrollment-collector.mjs"), "collector tests missing");
expect(workflow.includes("actual_certificate_signature_count === 0"),
  "zero-signature assertion missing");
expect(workflow.includes('external_quorum_status === "NOT_ESTABLISHED"'),
  "fail-closed quorum assertion missing");
expect(workflow.includes("independence_verified === false"),
  "independence assertion missing");
expect(individualWorkflow.includes("PR_AUTHOR_ID:"),
  "individual verifier lacks immutable GitHub author binding");
expect(individualWorkflow.includes("GITHUB_ACCOUNT_BINDING_MISMATCH"),
  "individual verifier lacks account mismatch rejection");
expect(individualWorkflow.includes("PERSONA_PATH_BINDING_MISMATCH"),
  "individual verifier lacks persona/path binding");
expect(individualWorkflow.includes("Project-owned or target-author PRs"),
  "individual verifier lacks project-owned exclusion");
expect(individualWorkflow.includes('PR_AUTHOR_ID}" == "258611371"'),
  "individual verifier lacks immutable project-owner ID exclusion");
expect(!individualWorkflow.includes("actions/checkout"),
  "individual verifier must not checkout applicant code");
expect(!/^\s+[A-Za-z-]+:\s+write\s*$/mu.test(individualWorkflow),
  "individual verifier has write permission");

const uses = [...workflow.matchAll(/^\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/gmu)]
  .map((match) => match[1]);
expect(uses.length === 1, "unexpected third-party action count");
expect(
  uses[0] === "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
  "artifact action is not pinned to the reviewed immutable commit",
);

process.stdout.write(`${JSON.stringify({
  schema: "lifepp.external-cai-open-enrollment-workflow-boundary-test.v1",
  trusted_base_only: true,
  individual_application_author_bound: true,
  applicant_code_executed: false,
  repository_write_permission: false,
  repository_mutation_command_present: false,
  immutable_action_pins: true,
  deterministic_readiness_rebuild_required: true,
  actual_certificate_signature_count: 0,
  external_quorum_status: "NOT_ESTABLISHED",
  independence_verified: false,
  authority_established: false,
}, null, 2)}\n`);
