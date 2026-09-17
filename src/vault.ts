import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
  link,
} from "node:fs/promises";
import { constants } from "node:fs";
import { homedir } from "node:os";
import { extname, isAbsolute, join, relative, resolve } from "node:path";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
} from "node:crypto";
import { normalizeBase32Secret, validatePeriod } from "./totp";
import { isKeyId, type VaultKeyStore, type IconStore } from "./ports";
import { isValidIconImage } from "./image-validation";
import type {
  AccountIcon,
  HashAlgorithm,
  OtpAccount,
  VaultData,
} from "./types";

const VAULT_VERSION = 1 as const;
const SCRYPT_N = 131_072;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAX_MEMORY = 256 * 1024 * 1024;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const MAX_VAULT_BYTES = 10 * 1024 * 1024;
const MAX_ACCOUNTS = 1_000;
const MAX_ICON_BYTES = 1 * 1024 * 1024;

export const DEFAULT_VAULT_DIRECTORY = join(
  homedir(),
  "Library",
  "Application Support",
  "ray-otp",
);

type KdfMetadata = {
  readonly name: "scrypt";
  readonly N: typeof SCRYPT_N;
  readonly r: typeof SCRYPT_R;
  readonly p: typeof SCRYPT_P;
  readonly salt: string;
};

type VaultEnvelope = {
  readonly magic: "ray-otp";
  readonly version: 1;
  readonly kdf: KdfMetadata;
  readonly cipher: "aes-256-gcm";
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
};

type KeychainEnvelope = {
  readonly magic: "ray-otp";
  readonly version: 2;
  readonly keyId: string;
  readonly cipher: "aes-256-gcm";
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
};

export type OpenVault = {
  readonly session: VaultSession;
  readonly data: VaultData;
};

export class VaultError extends Error {}

export class VaultMissingError extends VaultError {}

export class VaultSession {
  private isLocked = false;

  public constructor(
    private readonly key: Buffer,
    public readonly keyId: string,
  ) {}

  public get encryptionKey(): Buffer {
    if (this.isLocked) {
      throw new VaultError("The vault is locked.");
    }

    return this.key;
  }

  public lock(): void {
    if (!this.isLocked) {
      this.key.fill(0);
      this.isLocked = true;
    }
  }
}

/** Validates local image bytes and stores owner-only copies, without networking. */
export class FileIconStore implements IconStore {
  public readonly iconDirectory: string;

  public constructor(
    private readonly baseDirectory: string = DEFAULT_VAULT_DIRECTORY,
  ) {
    this.iconDirectory = join(baseDirectory, "icons");
  }

  /** Imports a decodable image of at most 1 MiB and one megapixel; rejects invalid input or I/O failures. */
  public async importIcon(
    sourcePath: string,
    accountId: string,
  ): Promise<string> {
    const inputPath = resolve(sourcePath);
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(accountId)) {
      throw new VaultError("The account identifier is invalid.");
    }
    const extension = extname(inputPath).toLowerCase();
    const format =
      extension === ".png"
        ? "png"
        : extension === ".jpg" || extension === ".jpeg"
          ? "jpeg"
          : null;
    if (format === null) {
      throw new VaultError("The custom icon must be a PNG or JPEG file.");
    }

    const bytes = await readIconBytes(inputPath);
    if (!isValidIconImage(bytes, format)) {
      throw new VaultError(
        "Choose a valid PNG or JPEG image of at most one megapixel.",
      );
    }

    await this.ensureDirectory();
    const destination = join(
      this.iconDirectory,
      `${accountId}-${randomBytes(8).toString("hex")}.${format}`,
    );
    // Write the exact bytes that passed validation; never reopen the source.
    await writeFile(destination, bytes, { flag: "wx", mode: 0o600 });
    return destination;
  }

  /** Removes managed custom assets only; filesystem failures reject the operation. */
  public async removeManagedIcon(icon: AccountIcon): Promise<void> {
    if (icon.kind !== "custom" || !this.isManagedPath(icon.path)) {
      return;
    }

    await rm(icon.path, { force: true });
  }

  private async ensureDirectory(): Promise<void> {
    await mkdir(this.iconDirectory, { recursive: true, mode: 0o700 });
    await chmod(this.iconDirectory, 0o700);
  }

  private isManagedPath(candidate: string): boolean {
    const pathDifference = relative(
      resolve(this.iconDirectory),
      resolve(candidate),
    );
    return (
      pathDifference !== "" &&
      !pathDifference.startsWith("..") &&
      !isAbsolute(pathDifference)
    );
  }
}

export class VaultStore {
  private readonly vaultPath: string;
  private readonly iconStore: FileIconStore;
  private mutationQueue: Promise<void> = Promise.resolve();

  public constructor(
    private readonly keys: VaultKeyStore,
    private readonly baseDirectory: string = DEFAULT_VAULT_DIRECTORY,
    private readonly beforeCommit: () => Promise<void> = async () => {},
  ) {
    this.vaultPath = join(baseDirectory, "vault.json");
    this.iconStore = new FileIconStore(baseDirectory);
  }

  public get icons(): IconStore {
    return this.iconStore;
  }

  public async status(): Promise<"missing" | "legacy" | "keychain"> {
    try {
      await stat(this.vaultPath);
      return (await this.readEnvelope()).version === 1 ? "legacy" : "keychain";
    } catch (error) {
      if (isFileNotFound(error)) {
        return "missing";
      }
      throw new VaultError("The vault could not be inspected.");
    }
  }

  public create(): Promise<OpenVault> {
    return this.serialize(async () => {
      if ((await this.status()) !== "missing")
        throw new VaultError("A vault already exists.");
      const session = await this.createSession();
      const data = createEmptyVault();
      try {
        await this.writeVault(session, data, true);
        return { session, data };
      } catch (error) {
        session.lock();
        throw error;
      }
    });
  }

  public async unlock(): Promise<OpenVault> {
    const envelope = await this.readEnvelope();
    if (envelope.version !== 2)
      throw new VaultError(
        "Migrate this vault using its existing master password.",
      );
    const key = await this.keys.read(envelope.keyId);
    try {
      const data = this.decrypt(envelope, key);
      return { session: new VaultSession(key, envelope.keyId), data };
    } catch (error) {
      key.fill(0);
      throw error;
    }
  }

  public migrate(password: string): Promise<OpenVault> {
    return this.serialize(async () => {
      const original = await readFile(this.vaultPath);
      if (original.length > MAX_VAULT_BYTES)
        throw new VaultError("The vault is too large.");
      const envelope = parseSavedEnvelope(
        JSON.parse(original.toString("utf8")) as unknown,
      );
      if (envelope.version !== 1)
        throw new VaultError("This vault has already been migrated.");
      validateMasterPassword(password);
      const legacyKey = await deriveKey(
        password,
        decodeEnvelopeField(envelope.kdf.salt, SALT_BYTES),
      );
      let data: VaultData;
      try {
        data = this.decrypt(envelope, legacyKey);
      } finally {
        legacyKey.fill(0);
      }
      const session = await this.createSession();
      try {
        await mkdir(this.baseDirectory, { recursive: true, mode: 0o700 });
        await chmod(this.baseDirectory, 0o700);
        const backup = join(this.baseDirectory, "vault.pre-keychain.json");
        try {
          const handle = await open(backup, "wx", 0o600);
          try {
            await handle.writeFile(original);
            await handle.sync();
          } finally {
            await handle.close();
          }
        } catch (error) {
          if (!isRecord(error) || error.code !== "EEXIST") throw error;
          if (!(await readFile(backup)).equals(original))
            throw new VaultError(
              "The existing migration backup differs. Preserve it before retrying migration.",
            );
        }
        await chmod(backup, 0o600);
        // Detect changes made outside this store while migration was pending.
        if (!(await readFile(this.vaultPath)).equals(original))
          throw new VaultError("The vault changed during migration. Retry.");
        await this.writeVault(session, data);
        return { session, data };
      } catch (error) {
        session.lock();
        throw error;
      }
    });
  }

  private async createSession(): Promise<VaultSession> {
    const id = randomUUID();
    const created = await this.keys.create(id);
    try {
      const readBack = await this.keys.read(id);
      if (created.length !== KEY_BYTES || !created.equals(readBack)) {
        readBack.fill(0);
        throw new VaultError("The Keychain key could not be verified.");
      }
      return new VaultSession(readBack, id);
    } finally {
      created.fill(0);
    }
  }

  private decrypt(
    envelope: VaultEnvelope | KeychainEnvelope,
    key: Buffer,
  ): VaultData {
    let plaintext: Buffer | undefined;
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        key,
        decodeEnvelopeField(envelope.nonce, NONCE_BYTES),
      );
      decipher.setAAD(
        Buffer.from(
          envelope.version === 1
            ? createMetadata(envelope.kdf, envelope.nonce)
            : keychainMetadata(envelope),
        ),
      );
      decipher.setAuthTag(decodeEnvelopeField(envelope.tag, TAG_BYTES));
      plaintext = Buffer.concat([
        decipher.update(decodeEnvelopeField(envelope.ciphertext)),
        decipher.final(),
      ]);
      return parseVaultData(
        JSON.parse(plaintext.toString("utf8")) as unknown,
        this.iconStore.iconDirectory,
      );
    } catch {
      throw new VaultError(
        envelope.version === 1
          ? "The password is incorrect or the vault is corrupted."
          : "The vault could not be decrypted. Its key or contents may be damaged.",
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.mutationQueue.then(operation);
    // A rejected mutation must not prevent the next explicitly requested retry.
    this.mutationQueue = result.then(
      () => {},
      () => {},
    );
    return result;
  }

  public save(session: VaultSession, data: VaultData): Promise<void> {
    return this.serialize(() => this.writeVault(session, data));
  }

  private async writeVault(
    session: VaultSession,
    data: VaultData,
    exclusive = false,
  ): Promise<void> {
    const validData = parseVaultData(data, this.iconStore.iconDirectory);
    const nonce = randomBytes(NONCE_BYTES);
    const metadata = {
      magic: "ray-otp" as const,
      version: 2 as const,
      keyId: session.keyId,
      cipher: "aes-256-gcm" as const,
      nonce: nonce.toString("base64url"),
    };
    const cipher = createCipheriv("aes-256-gcm", session.encryptionKey, nonce);
    cipher.setAAD(Buffer.from(keychainMetadata(metadata)));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(validData), "utf8"),
      cipher.final(),
    ]);
    const envelope: KeychainEnvelope = {
      ...metadata,
      ciphertext: ciphertext.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    };
    // Verify serialized ciphertext with the read-back key before replacing any file.
    this.decrypt(
      parseSavedEnvelope(JSON.parse(JSON.stringify(envelope)) as unknown),
      session.encryptionKey,
    );
    await this.atomicWrite(JSON.stringify(envelope), session, exclusive);
  }

  private async readEnvelope(): Promise<VaultEnvelope | KeychainEnvelope> {
    try {
      const file = await readFile(this.vaultPath, { encoding: "utf8" });
      if (Buffer.byteLength(file, "utf8") > MAX_VAULT_BYTES)
        throw new VaultError("The vault is too large.");
      return parseSavedEnvelope(JSON.parse(file) as unknown);
    } catch (error) {
      if (error instanceof VaultError) throw error;
      if (isFileNotFound(error))
        throw new VaultMissingError("The vault does not exist.");
      throw new VaultError("The vault could not be read.");
    }
  }

  private async atomicWrite(
    contents: string,
    session: VaultSession,
    exclusive: boolean,
  ): Promise<void> {
    await mkdir(this.baseDirectory, { recursive: true, mode: 0o700 });
    await chmod(this.baseDirectory, 0o700);
    const temporaryPath = join(
      this.baseDirectory,
      `.vault-${process.pid}-${randomBytes(8).toString("hex")}.tmp`,
    );

    try {
      await writeFile(temporaryPath, contents, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      await chmod(temporaryPath, 0o600);
      const handle = await open(temporaryPath, "r+");
      try {
        await handle.sync();
      } finally {
        await handle.close();
      }
      await this.beforeCommit();
      // Locking during asynchronous I/O invalidates this write before its commit.
      void session.encryptionKey;
      if (exclusive) await link(temporaryPath, this.vaultPath);
      else await rename(temporaryPath, this.vaultPath);
    } finally {
      await rm(temporaryPath, { force: true });
    }
  }
}

function keychainMetadata(
  envelope: Pick<KeychainEnvelope, "keyId" | "nonce">,
): string {
  return JSON.stringify({
    magic: "ray-otp",
    version: 2,
    keyId: envelope.keyId,
    cipher: "aes-256-gcm",
    nonce: envelope.nonce,
  });
}

function parseSavedEnvelope(value: unknown): VaultEnvelope | KeychainEnvelope {
  if (isRecord(value) && value.version === 1) return parseEnvelope(value);
  if (
    !isRecord(value) ||
    value.magic !== "ray-otp" ||
    value.version !== 2 ||
    value.cipher !== "aes-256-gcm" ||
    !isKeyId(value.keyId)
  )
    throw new VaultError("The vault format is unsupported.");
  const { nonce, ciphertext, tag, keyId } = value;
  if (
    typeof nonce !== "string" ||
    typeof ciphertext !== "string" ||
    typeof tag !== "string"
  )
    throw new VaultError("The vault encryption data is invalid.");
  decodeEnvelopeField(nonce, NONCE_BYTES);
  decodeEnvelopeField(tag, TAG_BYTES);
  decodeEnvelopeField(ciphertext);
  return {
    magic: "ray-otp",
    version: 2,
    cipher: "aes-256-gcm",
    keyId,
    nonce,
    ciphertext,
    tag,
  };
}

export function createEmptyVault(
  createdAt = new Date().toISOString(),
): VaultData {
  return { version: 1, createdAt, updatedAt: createdAt, accounts: [] };
}

export function validateMasterPassword(password: string): void {
  if (password.length < 12) {
    throw new VaultError(
      "The master password must contain at least 12 characters.",
    );
  }
}

function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolveKey, reject) => {
    scryptCallback(
      password.normalize("NFKC"),
      salt,
      KEY_BYTES,
      { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAX_MEMORY },
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }
        resolveKey(Buffer.from(derivedKey));
      },
    );
  });
}

function createMetadata(kdf: KdfMetadata, nonce: string): string {
  return JSON.stringify({
    magic: "ray-otp",
    version: 1,
    kdf,
    cipher: "aes-256-gcm",
    nonce,
  });
}

function parseEnvelope(value: unknown): VaultEnvelope {
  if (
    !isRecord(value) ||
    value.magic !== "ray-otp" ||
    value.version !== VAULT_VERSION ||
    value.cipher !== "aes-256-gcm"
  ) {
    throw new VaultError("The vault format is unsupported.");
  }

  const kdf = value.kdf;
  if (
    !isRecord(kdf) ||
    kdf.name !== "scrypt" ||
    kdf.N !== SCRYPT_N ||
    kdf.r !== SCRYPT_R ||
    kdf.p !== SCRYPT_P ||
    typeof kdf.salt !== "string"
  ) {
    throw new VaultError("The vault key-derivation parameters are invalid.");
  }

  for (const field of ["nonce", "ciphertext", "tag"] as const) {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      throw new VaultError("The vault encryption data is invalid.");
    }
  }

  const salt = kdf.salt;
  const nonce = value.nonce;
  const ciphertext = value.ciphertext;
  const tag = value.tag;
  if (
    typeof salt !== "string" ||
    typeof nonce !== "string" ||
    typeof ciphertext !== "string" ||
    typeof tag !== "string"
  ) {
    throw new VaultError("The vault encryption data is invalid.");
  }

  decodeEnvelopeField(salt, SALT_BYTES);
  decodeEnvelopeField(nonce, NONCE_BYTES);
  decodeEnvelopeField(tag, TAG_BYTES);
  decodeEnvelopeField(ciphertext);

  return {
    magic: "ray-otp",
    version: 1,
    kdf: {
      name: "scrypt",
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      salt,
    },
    cipher: "aes-256-gcm",
    nonce,
    ciphertext,
    tag,
  };
}

function parseVaultData(value: unknown, iconDirectory: string): VaultData {
  if (
    !isRecord(value) ||
    value.version !== 1 ||
    typeof value.createdAt !== "string" ||
    typeof value.updatedAt !== "string"
  ) {
    throw new VaultError("The vault data is invalid.");
  }

  if (!Array.isArray(value.accounts) || value.accounts.length > MAX_ACCOUNTS) {
    throw new VaultError("The vault account list is invalid.");
  }

  const accounts = value.accounts.map((account) =>
    parseAccount(account, iconDirectory),
  );
  const ids = new Set<string>();
  for (const account of accounts) {
    if (ids.has(account.id)) {
      throw new VaultError("The vault contains duplicate account IDs.");
    }
    ids.add(account.id);
  }

  return {
    version: 1,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    accounts,
  };
}

function parseAccount(value: unknown, iconDirectory: string): OtpAccount {
  if (!isRecord(value)) {
    throw new VaultError("The vault contains an invalid account.");
  }

  const id = readBoundedString(value.id, "account ID", 128);
  const name = readBoundedString(value.name, "account name", 200);
  const label =
    value.label === undefined
      ? undefined
      : readBoundedString(value.label, "account label", 200);
  const secret = normalizeBase32Secret(
    readBoundedString(value.secret, "account secret", 256),
  );
  const period = readInteger(value.period, "account period");
  validatePeriod(period);
  const algorithm = readAlgorithm(value.algorithm);
  if (value.digits !== 6) {
    throw new VaultError("Only six-digit OTP accounts are supported.");
  }
  const icon = parseAccountIcon(value.icon, iconDirectory);

  return {
    id,
    name,
    ...(label === undefined ? {} : { label }),
    secret,
    icon,
    period,
    algorithm,
    digits: 6,
  };
}

function parseAccountIcon(value: unknown, iconDirectory: string): AccountIcon {
  if (!isRecord(value) || typeof value.kind !== "string") {
    throw new VaultError("The vault contains an invalid account icon.");
  }

  if (value.kind === "builtin" && isBuiltinIconName(value.name)) {
    return { kind: "builtin", name: value.name };
  }

  if (
    value.kind === "custom" &&
    typeof value.path === "string" &&
    isManagedIconPath(value.path, iconDirectory)
  ) {
    return { kind: "custom", path: resolve(value.path) };
  }

  throw new VaultError("The vault contains an invalid account icon.");
}

function readBoundedString(
  value: unknown,
  field: string,
  maximumLength: number,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength
  ) {
    throw new VaultError(`The ${field} is invalid.`);
  }
  return value;
}

function readInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new VaultError(`The ${field} is invalid.`);
  }
  return value;
}

function readAlgorithm(value: unknown): HashAlgorithm {
  if (value === "sha1" || value === "sha256" || value === "sha512") {
    return value;
  }
  throw new VaultError("The account algorithm is invalid.");
}

function isBuiltinIconName(
  value: unknown,
): value is "aws" | "microsoft" | "generic" {
  return value === "aws" || value === "microsoft" || value === "generic";
}

function isManagedIconPath(candidate: string, iconDirectory: string): boolean {
  const pathDifference = relative(resolve(iconDirectory), resolve(candidate));
  return (
    pathDifference !== "" &&
    !pathDifference.startsWith("..") &&
    !isAbsolute(pathDifference)
  );
}

function decodeEnvelopeField(value: string, expectedBytes?: number): Buffer {
  let decoded: Buffer;
  try {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error("Invalid base64url");
    }
    decoded = Buffer.from(value, "base64url");
  } catch {
    throw new VaultError("The vault encryption data is invalid.");
  }

  if (
    decoded.length === 0 ||
    (expectedBytes !== undefined && decoded.length !== expectedBytes)
  ) {
    throw new VaultError("The vault encryption data is invalid.");
  }

  return decoded;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFileNotFound(error: unknown): boolean {
  return isRecord(error) && error.code === "ENOENT";
}

async function readIconBytes(path: string): Promise<Buffer> {
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const info = await handle.stat();
    if (!info.isFile())
      throw new VaultError("The selected icon is not a regular file.");
    if (info.size > MAX_ICON_BYTES)
      throw new VaultError("The selected icon must be 1 MiB or smaller.");
    const bytes = Buffer.alloc(MAX_ICON_BYTES + 1);
    let size = 0;
    while (size < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        size,
        bytes.length - size,
        null,
      );
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > MAX_ICON_BYTES)
      throw new VaultError("The selected icon must be 1 MiB or smaller.");
    return bytes.subarray(0, size);
  } finally {
    await handle.close();
  }
}
