import type { AccountIcon } from "./types";

/** Application-owned key storage boundary. Implementations reject unavailable keys. */
export interface VaultKeyStore {
  /** Creates a key for a new identifier; returns caller-owned key bytes. */
  create(keyId: string): Promise<Buffer>;
  /** Retrieves caller-owned key bytes; never creates a missing key. */
  read(keyId: string): Promise<Buffer>;
}

/** Local icon operations used by account management, independent of the UI. */
export interface IconStore {
  readonly iconDirectory: string;
  /** Validates and imports a local image; rejects unsupported or invalid input. */
  importIcon(sourcePath: string, accountId: string): Promise<string>;
  /** Removes only managed custom icons; rejects filesystem failures. */
  removeManagedIcon(icon: AccountIcon): Promise<void>;
}

/** Validates identifiers shared by the vault format and key-store adapters. */
export function isKeyId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  );
}
