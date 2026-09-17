import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const directory = await mkdtemp(join(tmpdir(), "ray-otp-keychain-test-"));
const sdk = execFileSync("/usr/bin/xcrun", ["--show-sdk-path"], {
  encoding: "utf8",
}).trim();
const target = `${process.arch === "arm64" ? "arm64" : "x86_64"}-apple-macosx13.0`;
try {
  const helper = join(directory, "helper");
  const harness = join(directory, "harness");
  for (const [source, output, flags] of [
    ["KeychainHelper.swift", helper, ["-D", "KEYCHAIN_TEST"]],
    ["KeychainIntegrationTests.swift", harness, []],
  ]) {
    execFileSync(
      "/usr/bin/xcrun",
      [
        "swiftc",
        "-sdk",
        sdk,
        "-target",
        target,
        ...flags,
        join(root, "native", source),
        "-o",
        output,
        "-framework",
        "Security",
      ],
      { stdio: "inherit" },
    );
    execFileSync("/usr/bin/codesign", ["--force", "--sign", "-", output], {
      stdio: "inherit",
    });
  }
  execFileSync(harness, [helper, directory], {
    stdio: "inherit",
    timeout: 60_000,
  });
} finally {
  await rm(directory, { recursive: true, force: true });
}
