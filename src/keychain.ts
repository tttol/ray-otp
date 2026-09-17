import { spawn } from "node:child_process";
import { isKeyId, type VaultKeyStore } from "./ports";

export class KeychainError extends Error {
  public constructor(public readonly code: string) {
    super(
      "Mac Keychain could not unlock the vault. Retry or check Keychain Access.",
    );
  }
}

/** Runs the bundled helper directly, keeping keys out of argv and diagnostics. */
export class MacKeychainStore implements VaultKeyStore {
  public constructor(
    private readonly helperPath: string,
    private readonly timeoutMs = 60_000,
  ) {}

  public create(keyId: string): Promise<Buffer> {
    return this.request("create", keyId);
  }

  public read(keyId: string): Promise<Buffer> {
    return this.request("read", keyId);
  }

  private request(
    operation: "create" | "read",
    keyId: string,
  ): Promise<Buffer> {
    if (!isKeyId(keyId))
      return Promise.reject(new KeychainError("invalid-request"));
    return new Promise((resolve, reject) => {
      const child = spawn(this.helperPath, [], {
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
      const chunks: Buffer[] = [];
      let total = 0;
      let finished = false;
      const finish = (error?: KeychainError, key?: Buffer): void => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        chunks.forEach((chunk) => chunk.fill(0));
        if (error) reject(error);
        else if (key) resolve(key);
      };
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish(new KeychainError("timeout"));
      }, this.timeoutMs);
      child.stdout.on("data", (chunk: Buffer) => {
        total += chunk.length;
        if (finished || total > 4096) {
          chunk.fill(0);
          child.kill("SIGKILL");
          finish(new KeychainError("invalid-response"));
        } else chunks.push(chunk);
      });
      // Never expose native diagnostics or subprocess error objects to the UI.
      child.stderr.on("data", (chunk: Buffer) => chunk.fill(0));
      child.on("error", () => finish(new KeychainError("helper-unavailable")));
      child.stdin.on("error", () =>
        finish(new KeychainError("helper-unavailable")),
      );
      child.on("close", (code) => {
        if (finished) return;
        const output = Buffer.concat(chunks);
        try {
          const value: unknown = JSON.parse(output.toString("utf8"));
          if (typeof value !== "object" || value === null) throw new Error();
          if ("error" in value) {
            const allowed = [
              "missing",
              "denied",
              "cancelled",
              "locked",
              "duplicate",
              "unavailable",
            ];
            throw new KeychainError(
              typeof value.error === "string" && allowed.includes(value.error)
                ? value.error
                : "unavailable",
            );
          }
          if (
            code !== 0 ||
            !("key" in value) ||
            typeof value.key !== "string" ||
            !/^[A-Za-z0-9+/]{43}=$/.test(value.key)
          )
            throw new Error();
          const key = Buffer.from(value.key, "base64");
          if (key.length !== 32) {
            key.fill(0);
            throw new Error();
          }
          finish(undefined, key);
        } catch (error) {
          finish(
            error instanceof KeychainError
              ? error
              : new KeychainError("invalid-response"),
          );
        } finally {
          output.fill(0);
        }
      });
      child.stdin.end(JSON.stringify({ operation, keyId }));
    });
  }
}
