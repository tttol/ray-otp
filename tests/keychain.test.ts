import assert from "node:assert/strict";
import { chmod } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { KeychainError, MacKeychainStore } from "../src/keychain";

const fixture = fileURLToPath(
  new URL("./fixtures/helper.mjs", import.meta.url),
);

test("read accepts a validated key through its private pipe", async () => {
  // Given
  await chmod(fixture, 0o700);
  const store = new MacKeychainStore(fixture);
  const expected = Buffer.alloc(32, 7);
  // When
  const actual = await store.read("00000001-0000-4000-8000-000000000000");
  // Then
  assert.deepEqual(actual, expected);
  actual.fill(0);
});

for (const [prefix, code] of [
  ["00000002", "cancelled"],
  ["00000003", "invalid-response"],
  ["00000004", "invalid-response"],
  ["00000005", "timeout"],
] as const) {
  test(`read safely reports ${code} from fixture ${prefix}`, async () => {
    // Given
    await chmod(fixture, 0o700);
    const store = new MacKeychainStore(fixture, 500);
    const expected = (error: unknown): boolean =>
      error instanceof KeychainError && error.code === code;
    // When
    const actual = store.read(`${prefix}-0000-4000-8000-000000000000`);
    // Then
    await assert.rejects(actual, expected);
  });
}

for (const [id, code] of [
  ["not-a-uuid", "invalid-request"],
  ["00000001-0000-4000-8000-000000000000", "helper-unavailable"],
] as const) {
  test(`read reports ${code} without subprocess diagnostics`, async () => {
    // Given
    const store = new MacKeychainStore("/nonexistent/ray-otp-helper");
    const expected = (error: unknown): boolean =>
      error instanceof KeychainError && error.code === code;
    // When
    const actual = store.read(id);
    // Then
    await assert.rejects(actual, expected);
  });
}
