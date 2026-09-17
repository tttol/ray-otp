import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  readFile,
  writeFile,
  mkdir,
  rename,
  chmod,
  rm,
} from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const source = join(root, "native/KeychainHelper.swift");
const output = join(root, "assets/keychain-helper");
const stampPath = join(root, "assets/keychain-helper.build.json");
const compiler = execFileSync("/usr/bin/xcrun", ["--find", "swiftc"], {
  encoding: "utf8",
}).trim();
const version = execFileSync(compiler, ["--version"], { encoding: "utf8" });
const sdk = execFileSync("/usr/bin/xcrun", ["--show-sdk-path"], {
  encoding: "utf8",
}).trim();
const target = `${process.arch === "arm64" ? "arm64" : "x86_64"}-apple-macosx13.0`;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fingerprint = hash(
  Buffer.concat([
    await readFile(source),
    await readFile(fileURLToPath(import.meta.url)),
    Buffer.from(version + sdk + target),
  ]),
);
let existing;
try {
  existing = JSON.parse(await readFile(stampPath, "utf8"));
} catch {
  /* First build. */
}
if (existing?.source === fingerprint) {
  try {
    if (existing.binary === hash(await readFile(output))) {
      execFileSync("/usr/bin/codesign", ["--verify", "--strict", output], {
        stdio: "pipe",
      });
      console.log("Keychain helper is up to date.");
      process.exit(0);
    }
  } catch {
    /* Rebuild a missing or invalid binary. */
  }
}
await mkdir(join(root, "assets"), { recursive: true });
const temporary = `${output}.${process.pid}.tmp`;
try {
  execFileSync(
    compiler,
    [
      "-O",
      "-sdk",
      sdk,
      "-target",
      target,
      source,
      "-o",
      temporary,
      "-framework",
      "Security",
    ],
    { stdio: "inherit" },
  );
  execFileSync(
    "/usr/bin/codesign",
    [
      "--force",
      "--sign",
      "-",
      "--identifier",
      "local.ray-otp.keychain-helper",
      temporary,
    ],
    { stdio: "inherit" },
  );
  await chmod(temporary, 0o700);
  await rename(temporary, output);
  await writeFile(
    stampPath,
    JSON.stringify({
      source: fingerprint,
      binary: hash(await readFile(output)),
    }) + "\n",
  );
} finally {
  await rm(temporary, { force: true });
}
