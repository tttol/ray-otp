import { createHmac } from "node:crypto";
import type { HashAlgorithm } from "./types";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const VALID_LENGTH_REMAINDERS = new Set([0, 2, 4, 5, 7]);

export type TotpOptions = {
  readonly period: number;
  readonly algorithm: HashAlgorithm;
  readonly digits?: 6;
};

/**
 * Normalizes a Base32 secret and rejects characters that cannot represent an OTP secret.
 */
export function normalizeBase32Secret(secret: string): string {
  const compact = secret.replace(/[\s-]/g, "").toUpperCase();
  const normalized = compact.replace(/=+$/g, "");

  if (normalized.length === 0) {
    throw new Error("The OTP secret is required.");
  }

  if (
    ![...normalized].every((character) => BASE32_ALPHABET.includes(character))
  ) {
    throw new Error("The OTP secret must be a valid Base32 value.");
  }

  if (!VALID_LENGTH_REMAINDERS.has(normalized.length % 8)) {
    throw new Error("The OTP secret has an invalid Base32 length.");
  }

  const padding = compact.length - normalized.length;
  const requiredPadding = (8 - (normalized.length % 8)) % 8;
  if (padding !== 0 && padding !== requiredPadding) {
    throw new Error("The OTP secret has invalid Base32 padding.");
  }

  // RFC 4648 encodings must not hide nonzero bits beyond the last whole byte.
  const unusedBits = (normalized.length * 5) % 8;
  const lastCharacter = normalized.charAt(normalized.length - 1);
  if (
    (BASE32_ALPHABET.indexOf(lastCharacter) & ((1 << unusedBits) - 1)) !==
    0
  ) {
    throw new Error("The OTP secret has nonzero Base32 padding bits.");
  }

  return normalized;
}

/**
 * Decodes an unpadded Base32 value into bytes.
 */
export function decodeBase32(secret: string): Buffer {
  const normalized = normalizeBase32Secret(secret);
  const bytes: number[] = [];
  let buffer = 0;
  let bitCount = 0;

  for (const character of normalized) {
    const value = BASE32_ALPHABET.indexOf(character);
    buffer = (buffer << 5) | value;
    bitCount += 5;

    while (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((buffer >> bitCount) & 0xff);
      buffer &= (1 << bitCount) - 1;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generates a six-digit RFC 6238 TOTP for a timestamp in milliseconds.
 */
export function generateTotp(
  secret: string,
  timestampMs: number,
  options: TotpOptions,
): string {
  const period = validatePeriod(options.period);
  const key = decodeBase32(secret);
  const counter = Math.floor(timestampMs / 1000 / period);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(options.algorithm, key)
    .update(counterBuffer)
    .digest();
  const lastByte = digest[digest.length - 1];
  if (lastByte === undefined) {
    throw new Error("The OTP digest is empty.");
  }
  const offset = lastByte & 0x0f;
  const firstByte = digest[offset];
  const secondByte = digest[offset + 1];
  const thirdByte = digest[offset + 2];
  const fourthByte = digest[offset + 3];
  if (
    firstByte === undefined ||
    secondByte === undefined ||
    thirdByte === undefined ||
    fourthByte === undefined
  ) {
    throw new Error("The OTP digest is invalid.");
  }
  const binary =
    ((firstByte & 0x7f) << 24) |
    ((secondByte & 0xff) << 16) |
    ((thirdByte & 0xff) << 8) |
    (fourthByte & 0xff);
  const code = binary % 1_000_000;

  return code.toString().padStart(6, "0");
}

/**
 * Returns the number of seconds remaining in the current TOTP period.
 */
export function getRemainingSeconds(
  timestampMs: number,
  period: number,
): number {
  const validatedPeriod = validatePeriod(period);
  const elapsed = Math.floor(timestampMs / 1000) % validatedPeriod;
  return validatedPeriod - elapsed;
}

export function validatePeriod(period: number): number {
  if (!Number.isInteger(period) || period <= 0 || period > 86_400) {
    throw new Error(
      "The OTP period must be a whole number between 1 and 86400 seconds.",
    );
  }

  return period;
}
