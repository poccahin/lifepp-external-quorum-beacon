import {execFileSync} from "node:child_process";
import {createHash, generateKeyPairSync} from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {basename, dirname, isAbsolute, relative, resolve, sep} from "node:path";
import {fileURLToPath} from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));

const parseArgs = (argv) => {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("USAGE: --private-key <absolute-path> --public-key <absolute-path>");
    }
    if (Object.hasOwn(result, key)) throw new Error(`DUPLICATE_ARGUMENT:${key}`);
    result[key] = value;
  }
  const allowed = new Set(["--private-key", "--public-key"]);
  if (Object.keys(result).some((key) => !allowed.has(key)) ||
      !result["--private-key"] || !result["--public-key"]) {
    throw new Error("USAGE: --private-key <absolute-path> --public-key <absolute-path>");
  }
  return result;
};

const inside = (root, candidate) => {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
};

const writeNew = (path, value, mode) => {
  const descriptor = openSync(path, "wx", mode);
  let complete = false;
  try {
    writeFileSync(descriptor, value, {encoding: "utf8"});
    chmodSync(path, mode);
    complete = true;
  } finally {
    closeSync(descriptor);
    if (!complete && existsSync(path)) unlinkSync(path);
  }
};

const canonicalDestination = (path) => {
  const absolute = resolve(path);
  let ancestor = dirname(absolute);
  const missing = [];
  while (!existsSync(ancestor)) {
    missing.unshift(basename(ancestor));
    const parent = dirname(ancestor);
    if (parent === ancestor) throw new Error("NO_EXISTING_PATH_ANCESTOR");
    ancestor = parent;
  }
  return resolve(realpathSync(ancestor), ...missing, basename(absolute));
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

const args = parseArgs(process.argv.slice(2));
const privatePath = args["--private-key"];
const publicPath = args["--public-key"];
if (!isAbsolute(privatePath) || !isAbsolute(publicPath)) {
  throw new Error("KEY_PATHS_MUST_BE_ABSOLUTE");
}
if (resolve(privatePath) === resolve(publicPath)) throw new Error("KEY_PATHS_MUST_DIFFER");

const resolvedPrivatePath = canonicalDestination(privatePath);
const resolvedPublicPath = canonicalDestination(publicPath);

const worktreeRoots = [...new Set([
  gitWorktreeRoot(SCRIPT_DIRECTORY),
  gitWorktreeRoot(process.cwd()),
].filter(Boolean))];
if (worktreeRoots.some((worktree) => inside(worktree, resolvedPrivatePath))) {
  throw new Error("PRIVATE_KEY_PATH_MUST_BE_OUTSIDE_GIT_WORKTREE");
}

mkdirSync(dirname(resolvedPrivatePath), {recursive: true, mode: 0o700});
mkdirSync(dirname(resolvedPublicPath), {recursive: true, mode: 0o755});
if (existsSync(resolvedPrivatePath) || existsSync(resolvedPublicPath)) {
  throw new Error("KEY_OUTPUT_ALREADY_EXISTS");
}

const {privateKey, publicKey} = generateKeyPairSync("ed25519");
const privatePem = privateKey.export({type: "pkcs8", format: "pem"});
const publicPem = publicKey.export({type: "spki", format: "pem"});
const fingerprint = `sha256:${createHash("sha256")
  .update(publicKey.export({type: "spki", format: "der"}))
  .digest("hex")}`;

let privateCreated = false;
let publicCreated = false;
try {
  writeNew(resolvedPrivatePath, privatePem, 0o600);
  privateCreated = true;
  writeNew(resolvedPublicPath, publicPem, 0o644);
  publicCreated = true;
} catch (error) {
  if (privateCreated && existsSync(resolvedPrivatePath)) unlinkSync(resolvedPrivatePath);
  if (publicCreated && existsSync(resolvedPublicPath)) unlinkSync(resolvedPublicPath);
  throw error;
}

console.log(JSON.stringify({
  valid: true,
  key_type: "Ed25519",
  private_key_path: resolvedPrivatePath,
  public_key_path: resolvedPublicPath,
  public_key_fingerprint: fingerprint,
  private_key_emitted: false,
  authority_established: false,
}));
