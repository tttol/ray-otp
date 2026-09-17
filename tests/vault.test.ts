import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, writeFile, rm } from "node:fs/promises";
import {
  randomBytes,
  randomUUID,
  createCipheriv,
  scryptSync,
} from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { VaultError, VaultStore, createEmptyVault } from "../src/vault";
import { KeychainError } from "../src/keychain";
import type { VaultKeyStore } from "../src/ports";
import type { OtpAccount } from "../src/types";

const password = "synthetic migration password";
const testAccount: OtpAccount = {
  id: "account-1",
  name: "AWS",
  label: "root",
  secret: "JBSWY3DPEHPK3PXP",
  icon: { kind: "builtin", name: "aws" },
  period: 30,
  algorithm: "sha1",
  digits: 6,
};

class MemoryKeys implements VaultKeyStore {
  public readonly values = new Map<string, Buffer>();
  public creates = 0;
  public async create(id: string): Promise<Buffer> {
    this.creates++;
    assert.equal(this.values.has(id), false, "Fixture keys must be unique");
    const key = randomBytes(32);
    this.values.set(id, key);
    return Buffer.from(key);
  }
  public async read(id: string): Promise<Buffer> {
    const key = this.values.get(id);
    assert.ok(key, "Fixture key must exist");
    return Buffer.from(key);
  }
}

async function setup(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), "ray-otp-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keys = new MemoryKeys();
  return {
    directory,
    keys,
    store: new VaultStore(keys, directory),
    path: join(directory, "vault.json"),
  };
}

// Independently construct the legacy wire format, using its original authenticated metadata.
async function legacyFile(directory: string): Promise<Buffer> {
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const kdf = {
    name: "scrypt",
    N: 131072,
    r: 8,
    p: 1,
    salt: salt.toString("base64url"),
  };
  const metadata = {
    magic: "ray-otp",
    version: 1,
    kdf,
    cipher: "aes-256-gcm",
    nonce: nonce.toString("base64url"),
  };
  const key = scryptSync(password, salt, 32, {
    N: 131072,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(metadata)));
  const data = { ...createEmptyVault(), accounts: [testAccount] };
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data)),
    cipher.final(),
  ]);
  key.fill(0);
  const file = Buffer.from(
    JSON.stringify({
      ...metadata,
      ciphertext: encrypted.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    }),
  );
  await writeFile(join(directory, "vault.json"), file, { mode: 0o600 });
  return file;
}

test("create installs an encrypted owner-only version-2 vault", async (t) => {
  // Given
  const { directory, store, path } = await setup(t);
  const expected = {
    accounts: [],
    version: 2,
    fileMode: 0o600,
    directoryMode: 0o700,
  };
  // When
  const actual = await store.create();
  // Then
  const envelope: unknown = JSON.parse(await readFile(path, "utf8"));
  assert.ok(
    typeof envelope === "object" && envelope !== null && "version" in envelope,
  );
  assert.deepEqual(
    {
      accounts: actual.data.accounts,
      version: envelope.version,
      fileMode: (await stat(path)).mode & 0o777,
      directoryMode: (await stat(directory)).mode & 0o777,
    },
    expected,
  );
  actual.session.lock();
});

test("unlock restores saved accounts after restarting without a password", async (t) => {
  // Given
  const { directory, keys, store } = await setup(t);
  const created = await store.create();
  const expected = { ...created.data, accounts: [testAccount] };
  await store.save(created.session, expected);
  created.session.lock();
  const restarted = new VaultStore(keys, directory);
  // When
  const actual = await restarted.unlock();
  // Then
  assert.deepEqual(actual.data, expected);
  actual.session.lock();
});

test("save never persists plaintext account secrets or names", async (t) => {
  // Given
  const { store, path } = await setup(t);
  const created = await store.create();
  const expected = { secret: false, name: false };
  // When
  await store.save(created.session, {
    ...created.data,
    accounts: [testAccount],
  });
  // Then
  const actual = await readFile(path, "utf8");
  assert.deepEqual(
    {
      secret: actual.includes(testAccount.secret),
      name: actual.includes(testAccount.name),
    },
    expected,
  );
  created.session.lock();
});

test("migrate preserves accounts and an exact owner-only legacy backup", async (t) => {
  // Given
  const { directory, store } = await setup(t);
  const original = await legacyFile(directory);
  const backup = join(directory, "vault.pre-keychain.json");
  const expected = { accounts: [testAccount], backup: original, mode: 0o600 };
  // When
  const actual = await store.migrate(password);
  // Then
  assert.deepEqual(
    {
      accounts: actual.data.accounts,
      backup: await readFile(backup),
      mode: (await stat(backup)).mode & 0o777,
    },
    expected,
  );
  actual.session.lock();
});

test("unlock restores migrated accounts after restarting", async (t) => {
  // Given
  const { directory, store, keys } = await setup(t);
  await legacyFile(directory);
  const migrated = await store.migrate(password);
  const expected = migrated.data;
  migrated.session.lock();
  const restarted = new VaultStore(keys, directory);
  // When
  const actual = await restarted.unlock();
  // Then
  assert.deepEqual(actual.data, expected);
  actual.session.lock();
});

test("migrate rejects already migrated data without changing it", async (t) => {
  // Given
  const { directory, store, path } = await setup(t);
  await legacyFile(directory);
  const migrated = await store.migrate(password);
  migrated.session.lock();
  const expected = await readFile(path);
  // When
  const actual = store.migrate(password);
  // Then
  await assert.rejects(actual, VaultError);
  assert.deepEqual(await readFile(path), expected);
});

test("migrate with an incorrect password preserves the file and key store", async (t) => {
  // Given
  const { directory, store, keys, path } = await setup(t);
  const original = await legacyFile(directory);
  const expected = { bytes: original, creates: 0 };
  // When
  const actual = store.migrate("incorrect but long password");
  // Then
  await assert.rejects(actual, VaultError);
  assert.deepEqual(
    { bytes: await readFile(path), creates: keys.creates },
    expected,
  );
});

test("create does not install a vault when key readback fails", async (t) => {
  // Given
  const { directory, keys, path } = await setup(t);
  const unavailable: VaultKeyStore = {
    create: (id) => keys.create(id),
    read: async () => {
      throw new KeychainError("denied");
    },
  };
  const store = new VaultStore(unavailable, directory);
  const expected = { code: "ENOENT" };
  // When
  const actual = store.create();
  // Then
  await assert.rejects(actual, KeychainError);
  await assert.rejects(stat(path), expected);
});

test("migrate preserves legacy bytes when key readback fails", async (t) => {
  // Given
  const { directory, keys, path } = await setup(t);
  const expected = await legacyFile(directory);
  const unavailable: VaultKeyStore = {
    create: (id) => keys.create(id),
    read: async () => {
      throw new KeychainError("cancelled");
    },
  };
  const store = new VaultStore(unavailable, directory);
  // When
  const actual = store.migrate(password);
  // Then
  await assert.rejects(actual, KeychainError);
  assert.deepEqual(await readFile(path), expected);
});

test("save serializes concurrent submissions in order", async (t) => {
  // Given
  const { store } = await setup(t);
  const created = await store.create();
  const laterAccount = { ...testAccount, name: "Microsoft" };
  const expected = { ...created.data, accounts: [laterAccount] };
  // When
  await Promise.all([
    store.save(created.session, { ...created.data, accounts: [testAccount] }),
    store.save(created.session, expected),
  ]);
  // Then
  const actual = await store.unlock();
  assert.deepEqual(actual.data, expected);
  actual.session.lock();
  created.session.lock();
});

test("save uses a fresh nonce", async (t) => {
  // Given
  const { store, path } = await setup(t);
  const created = await store.create();
  const expected = (await readEnvelope(path)).nonce;
  // When
  await store.save(created.session, created.data);
  // Then
  assert.notEqual((await readEnvelope(path)).nonce, expected);
  created.session.lock();
});

test("migrate preserves both original and backup when replacement fails", async (t) => {
  // Given
  const { directory, keys, path } = await setup(t);
  const original = await legacyFile(directory);
  const failing = new VaultStore(keys, directory, async () => {
    throw new Error("synthetic disk failure");
  });
  const expected = { original, backup: original };
  // When
  const actual = failing.migrate(password);
  // Then
  await assert.rejects(actual, /synthetic disk failure/);
  assert.deepEqual(
    {
      original: await readFile(path),
      backup: await readFile(join(directory, "vault.pre-keychain.json")),
    },
    expected,
  );
});

test("migrate can retry after an interrupted replacement with the same backup", async (t) => {
  // Given
  const { directory, keys, store } = await setup(t);
  await legacyFile(directory);
  const failing = new VaultStore(keys, directory, async () => {
    throw new Error("synthetic disk failure");
  });
  await assert.rejects(failing.migrate(password));
  const expected = [testAccount];
  // When
  const actual = await store.migrate(password);
  // Then
  assert.deepEqual(actual.data.accounts, expected);
  actual.session.lock();
});

test("migrate never overwrites a different existing backup", async (t) => {
  // Given
  const { directory, store, path } = await setup(t);
  const original = await legacyFile(directory);
  const backup = join(directory, "vault.pre-keychain.json");
  const previous = Buffer.from("existing backup bytes");
  await writeFile(backup, previous);
  const expected = { original, backup: previous };
  // When
  const actual = store.migrate(password);
  // Then
  await assert.rejects(actual, VaultError);
  assert.deepEqual(
    { original: await readFile(path), backup: await readFile(backup) },
    expected,
  );
});

for (const failure of ["missing", "denied", "cancelled", "locked"]) {
  test(`unlock with Keychain ${failure} never regenerates or changes the vault`, async (t) => {
    // Given
    const { store, keys, path } = await setup(t);
    const created = await store.create();
    created.session.lock();
    const expected = { bytes: await readFile(path), creates: 1 };
    keys.read = async () => {
      throw new KeychainError(failure);
    };
    // When
    const actual = store.unlock();
    // Then
    await assert.rejects(actual, KeychainError);
    assert.deepEqual(
      { bytes: await readFile(path), creates: keys.creates },
      expected,
    );
  });
}

test("unlock rejects ciphertext tampering", async (t) => {
  // Given
  const { store, path } = await setup(t);
  const created = await store.create();
  created.session.lock();
  const envelope = await readEnvelope(path);
  const ciphertext = Buffer.from(envelope.ciphertext, "base64url");
  ciphertext.writeUInt8(ciphertext.readUInt8(0) ^ 1, 0);
  await writeFile(
    path,
    JSON.stringify({
      ...envelope,
      ciphertext: ciphertext.toString("base64url"),
    }),
  );
  const expected = VaultError;
  // When
  const actual = store.unlock();
  // Then
  await assert.rejects(actual, expected);
});

test("unlock authenticates the key identifier even when key bytes match", async (t) => {
  // Given
  const { store, keys, path } = await setup(t);
  const created = await store.create();
  created.session.lock();
  const envelope = await readEnvelope(path);
  const sameKey = await keys.read(envelope.keyId);
  const keyId = randomUUID();
  keys.values.set(keyId, sameKey);
  await writeFile(path, JSON.stringify({ ...envelope, keyId }));
  const expected = VaultError;
  // When
  const actual = store.unlock();
  // Then
  await assert.rejects(actual, expected);
});

test("status rejects malformed files", async (t) => {
  // Given
  const { store, path } = await setup(t);
  await writeFile(path, "{broken");
  const expected = VaultError;
  // When
  const actual = store.status();
  // Then
  await assert.rejects(actual, expected);
});

test("status identifies a legacy envelope", async (t) => {
  // Given
  const { store, directory } = await setup(t);
  await legacyFile(directory);
  const expected = "legacy";
  // When
  const actual = await store.status();
  // Then
  assert.equal(actual, expected);
});

test("create serializes duplicate submissions", async (t) => {
  // Given
  const { store, keys } = await setup(t);
  const expected = { statuses: ["fulfilled", "rejected"], creates: 1 };
  // When
  const actual = await Promise.allSettled([store.create(), store.create()]);
  // Then
  assert.deepEqual(
    { statuses: actual.map((result) => result.status), creates: keys.creates },
    expected,
  );
});

test("create cannot overwrite an existing vault", async (t) => {
  // Given
  const { store, path } = await setup(t);
  const created = await store.create();
  created.session.lock();
  const expected = await readFile(path);
  // When
  const actual = store.create();
  // Then
  await assert.rejects(actual, VaultError);
  assert.deepEqual(await readFile(path), expected);
});

test("save rejects a session locked before commit", async (t) => {
  // Given
  const { directory, keys, store, path } = await setup(t);
  const created = await store.create();
  const expected = await readFile(path);
  const delayed = new VaultStore(keys, directory, async () =>
    created.session.lock(),
  );
  const data = { ...created.data, accounts: [testAccount] };
  // When
  const actual = delayed.save(created.session, data);
  // Then
  await assert.rejects(actual, VaultError);
  assert.deepEqual(await readFile(path), expected);
});

test("save preserves the original file when a write fails", async (t) => {
  // Given
  const { directory, keys, store, path } = await setup(t);
  const created = await store.create();
  const expected = await readFile(path);
  const failing = new VaultStore(keys, directory, async () => {
    throw new Error("synthetic failure");
  });
  const data = { ...created.data, accounts: [testAccount] };
  // When
  const actual = failing.save(created.session, data);
  // Then
  await assert.rejects(actual, /synthetic failure/);
  assert.deepEqual(await readFile(path), expected);
  created.session.lock();
});

test("save remains usable after a prior queued write failure", async (t) => {
  // Given
  const { directory, keys, store } = await setup(t);
  const created = await store.create();
  const steps = [
    async () => {
      throw new Error("synthetic failure");
    },
    async () => {},
  ];
  const retryable = new VaultStore(keys, directory, async () => {
    const step = steps.shift();
    assert.ok(step, "Unexpected commit");
    await step();
  });
  const expected = { ...created.data, accounts: [testAccount] };
  await assert.rejects(retryable.save(created.session, expected));
  // When
  await retryable.save(created.session, expected);
  // Then
  const actual = await store.unlock();
  assert.deepEqual(actual.data, expected);
  actual.session.lock();
  created.session.lock();
});

async function readEnvelope(
  path: string,
): Promise<
  Record<string, unknown> & { ciphertext: string; keyId: string; nonce: string }
> {
  const value: unknown = JSON.parse(await readFile(path, "utf8"));
  assert.ok(typeof value === "object" && value !== null);
  assert.ok("ciphertext" in value && typeof value.ciphertext === "string");
  assert.ok("keyId" in value && typeof value.keyId === "string");
  assert.ok("nonce" in value && typeof value.nonce === "string");
  return {
    ...value,
    ciphertext: value.ciphertext,
    keyId: value.keyId,
    nonce: value.nonce,
  };
}
