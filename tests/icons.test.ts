import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { PNG } from "pngjs";
import { encode } from "jpeg-js";
import { FileIconStore, VaultError } from "../src/vault";
import { isValidIconImage } from "../src/image-validation";

const pixels = { width: 2, height: 2, data: Buffer.alloc(16, 255) };
const pngImage = new PNG({ width: pixels.width, height: pixels.height });
pngImage.data = Buffer.from(pixels.data);
const png = PNG.sync.write(pngImage);
const jpeg = encode(pixels).data;
const corruptedPng = Buffer.from(png);
corruptedPng.writeUInt8(corruptedPng.readUInt8(40) ^ 1, 40);
const oversizedPng = Buffer.from(png);
oversizedPng.writeUInt32BE(1_000_001, 16);
const duplicateHeaderPng = Buffer.concat([
  png.subarray(0, 33),
  png.subarray(8),
]);

async function setup(
  t: TestContext,
): Promise<{ directory: string; store: FileIconStore }> {
  const directory = await mkdtemp(join(tmpdir(), "ray-otp-icon-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, store: new FileIconStore(directory) };
}

for (const [format, bytes] of [
  ["png", png],
  ["jpeg", jpeg],
] as const) {
  test(`isValidIconImage decodes a complete ${format}`, () => {
    // Given
    const expected = true;
    // When
    const actual = isValidIconImage(bytes, format);
    // Then
    assert.equal(actual, expected);
  });

  test(`importIcon copies exactly validated ${format} bytes with private permissions`, async (t) => {
    // Given
    const { directory, store } = await setup(t);
    const source = join(directory, `source.${format}`);
    await writeFile(source, bytes);
    const expected = { bytes, mode: 0o600, directoryMode: 0o700 };
    // When
    const path = await store.importIcon(source, "account-1");
    // Then
    assert.deepEqual(
      {
        bytes: await readFile(path),
        mode: (await stat(path)).mode & 0o777,
        directoryMode: (await stat(store.iconDirectory)).mode & 0o777,
      },
      expected,
    );
  });
}

for (const [description, format, bytes] of [
  ["PNG signature only", "png", png.subarray(0, 8)],
  ["JPEG signature only", "jpeg", Buffer.from([255, 216, 255])],
  ["truncated PNG", "png", png.subarray(0, -12)],
  ["truncated JPEG", "jpeg", jpeg.subarray(0, -20)],
  ["PNG checksum corruption", "png", corruptedPng],
  ["oversized PNG dimensions", "png", oversizedPng],
  ["duplicate PNG header", "png", duplicateHeaderPng],
  ["mismatched extension", "jpeg", png],
] as const) {
  test(`isValidIconImage rejects ${description}`, () => {
    // Given
    const expected = false;
    // When
    const actual = isValidIconImage(bytes, format);
    // Then
    assert.equal(actual, expected);
  });

  test(`importIcon rejects ${description} without creating an asset`, async (t) => {
    // Given
    const { directory, store } = await setup(t);
    const source = join(directory, `source.${format}`);
    await writeFile(source, bytes);
    const expected = ["source." + format];
    // When
    const actual = store.importIcon(source, "account-1");
    // Then
    await assert.rejects(actual, VaultError);
    assert.deepEqual(await readdir(directory), expected);
  });
}

test("importIcon rejects files larger than 1 MiB", async (t) => {
  // Given
  const { directory, store } = await setup(t);
  const source = join(directory, "large.png");
  await writeFile(source, Buffer.alloc(1024 * 1024 + 1));
  const expected = /1 MiB/;
  // When
  const actual = store.importIcon(source, "account-1");
  // Then
  await assert.rejects(actual, expected);
});

test("importIcon rejects symbolic links", async (t) => {
  // Given
  const { directory, store } = await setup(t);
  const source = join(directory, "source.png");
  const link = join(directory, "link.png");
  await writeFile(source, png);
  await symlink(source, link);
  const expected = { code: "ELOOP" };
  // When
  const actual = store.importIcon(link, "account-1");
  // Then
  await assert.rejects(actual, expected);
});

for (const accountId of ["../escape", "", "a/b"]) {
  test(`importIcon rejects unsafe account identifier ${JSON.stringify(accountId)}`, async (t) => {
    // Given
    const { directory, store } = await setup(t);
    const source = join(directory, "source.png");
    await writeFile(source, png);
    const expected = /identifier/;
    // When
    const actual = store.importIcon(source, accountId);
    // Then
    await assert.rejects(actual, expected);
  });
}

test("importIcon rejects unsupported extensions", async (t) => {
  // Given
  const { directory, store } = await setup(t);
  const source = join(directory, "source.svg");
  await writeFile(source, png);
  const expected = /PNG or JPEG/;
  // When
  const actual = store.importIcon(source, "account-1");
  // Then
  await assert.rejects(actual, expected);
});

test("removeManagedIcon deletes a managed custom image", async (t) => {
  // Given
  const { directory, store } = await setup(t);
  const source = join(directory, "source.png");
  await writeFile(source, png);
  const path = await store.importIcon(source, "account-1");
  const expected = { code: "ENOENT" };
  // When
  await store.removeManagedIcon({ kind: "custom", path });
  // Then
  await assert.rejects(stat(path), expected);
});

test("removeManagedIcon preserves files outside the managed directory", async (t) => {
  // Given
  const { directory, store } = await setup(t);
  const path = join(directory, "source.png");
  await writeFile(path, png);
  const expected = png;
  // When
  await store.removeManagedIcon({ kind: "custom", path });
  // Then
  assert.deepEqual(await readFile(path), expected);
});
