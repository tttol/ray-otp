import assert from "node:assert/strict";
import test from "node:test";
import { cleanupAccountIcon } from "../src/account-icons";
import type { IconStore } from "../src/ports";
import type { AccountIcon } from "../src/types";

const custom: AccountIcon = {
  kind: "custom",
  path: "/synthetic/icons/new.png",
};
const builtin: AccountIcon = { kind: "builtin", name: "generic" };

for (const candidate of [undefined, builtin, custom]) {
  test(`cleanupAccountIcon retains ${candidate?.kind ?? "absent"} icons still in use`, async () => {
    // Given
    const calls: AccountIcon[] = [];
    const store: IconStore = {
      iconDirectory: "/synthetic/icons",
      importIcon: async () => "unused",
      removeManagedIcon: async (icon) => {
        calls.push(icon);
      },
    };
    const expected = { result: "not-needed", calls: [] };
    // When
    const result = await cleanupAccountIcon(store, candidate, custom);
    // Then
    assert.deepEqual({ result, calls }, expected);
  });
}

test("cleanupAccountIcon removes an unreferenced imported icon", async () => {
  // Given
  const calls: AccountIcon[] = [];
  const store: IconStore = {
    iconDirectory: "/synthetic/icons",
    importIcon: async () => "unused",
    removeManagedIcon: async (icon) => {
      calls.push(icon);
    },
  };
  const expected = { result: "removed", calls: [custom] };
  // When
  const result = await cleanupAccountIcon(store, custom, builtin);
  // Then
  assert.deepEqual({ result, calls }, expected);
});

test("cleanupAccountIcon reports deletion failure without rejecting the save error handler", async () => {
  // Given
  const store: IconStore = {
    iconDirectory: "/synthetic/icons",
    importIcon: async () => "unused",
    removeManagedIcon: async () => {
      throw new Error("synthetic permission failure");
    },
  };
  const expected = "failed";
  // When
  const actual = await cleanupAccountIcon(store, custom, builtin);
  // Then
  assert.equal(actual, expected);
});
