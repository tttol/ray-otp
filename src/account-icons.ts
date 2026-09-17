import type { IconStore } from "./ports";
import type { AccountIcon } from "./types";

/**
 * Removes an unreferenced custom icon without masking an earlier save failure.
 * Returns an explicit failure result so the UI can report incomplete cleanup.
 */
export async function cleanupAccountIcon(
  store: IconStore,
  candidate: AccountIcon | undefined,
  retained: AccountIcon | undefined,
): Promise<"not-needed" | "removed" | "failed"> {
  if (
    candidate?.kind !== "custom" ||
    (retained?.kind === "custom" && candidate.path === retained.path)
  ) {
    return "not-needed";
  }
  try {
    await store.removeManagedIcon(candidate);
    return "removed";
  } catch {
    return "failed";
  }
}
