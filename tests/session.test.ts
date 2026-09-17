import assert from "node:assert/strict";
import test from "node:test";
import { VaultSession } from "../src/vault";
import { SessionGuard } from "../src/session";

const keyId = "00000001-0000-4000-8000-000000000000";

for (const [now, expected] of [
  [299_999, true],
  [300_000, false],
  [600_000, false],
] as const) {
  test(`usable checks the deadline after resume at ${now}ms`, () => {
    // Given
    let clock = 0;
    const guard = new SessionGuard(() => clock);
    guard.open(new VaultSession(Buffer.alloc(32, 7), keyId));
    clock = now;
    // When
    const actual = guard.usable();
    // Then
    assert.equal(actual, expected);
  });
  test(`touch cannot revive an expired session at ${now}ms`, () => {
    // Given
    let clock = 0;
    const guard = new SessionGuard(() => clock);
    guard.open(new VaultSession(Buffer.alloc(32, 7), keyId));
    clock = now;
    // When
    const actual = guard.touch();
    // Then
    assert.equal(actual, expected);
  });
}

test("touch extends a usable session's deadline", () => {
  // Given
  let now = 0;
  const guard = new SessionGuard(() => now);
  guard.open(new VaultSession(Buffer.alloc(32, 7), keyId));
  now = 299_000;
  const expected = true;
  // When
  guard.touch();
  // Then
  now = 300_000;
  assert.equal(guard.usable(), expected);
});

test("lock invalidates pending operations and wipes the owned key", () => {
  // Given
  const key = Buffer.alloc(32, 7);
  const guard = new SessionGuard(() => 0);
  guard.open(new VaultSession(key, keyId));
  const token = guard.token;
  const expected = { current: false, usable: false, key: Buffer.alloc(32) };
  // When
  guard.lock();
  // Then
  assert.deepEqual(
    { current: guard.current(token), usable: guard.usable(token), key },
    expected,
  );
});

test("touch rejects a pending operation from a previous session", () => {
  // Given
  const guard = new SessionGuard(() => 0);
  guard.open(new VaultSession(Buffer.alloc(32, 7), keyId));
  const pending = guard.token;
  guard.lock();
  guard.open(new VaultSession(Buffer.alloc(32, 8), keyId));
  const expected = false;
  // When
  const actual = guard.touch(pending);
  // Then
  assert.equal(actual, expected);
});

test("a locked VaultSession rejects key access", () => {
  // Given
  const session = new VaultSession(Buffer.alloc(32, 7), keyId);
  session.lock();
  const expected = /locked/;
  // When
  const actual = () => session.encryptionKey;
  // Then
  assert.throws(actual, expected);
});
