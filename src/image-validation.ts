import { inflateSync } from "node:zlib";
import { PNG } from "pngjs";
import { decode } from "jpeg-js";

const MAX_PIXELS = 1_000_000;
const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

/**
 * Decodes a local image with bounded allocation. Returns false for corrupt,
 * truncated, unsupported, or oversized images without exposing decoder errors.
 */
export function isValidIconImage(
  bytes: Buffer,
  format: "png" | "jpeg",
): boolean {
  try {
    if (format === "png") {
      preflightPng(bytes);
      const image = PNG.sync.read(bytes, { checkCRC: true });
      return image.data.length === image.width * image.height * 4;
    }
    const image = decode(bytes, {
      tolerantDecoding: false,
      maxResolutionInMP: 1,
      maxMemoryUsageInMB: 32,
    });
    return (
      image.width > 0 &&
      image.height > 0 &&
      image.data.length === image.width * image.height * 4
    );
  } catch {
    return false;
  }
}

// pngjs's interlaced path does not bound inflation. Validate all dimensions and
// cap decompression first, including duplicate headers and truncated chunks.
function preflightPng(bytes: Buffer): void {
  if (!bytes.subarray(0, 8).equals(PNG_SIGNATURE))
    throw new Error("Invalid PNG");
  let offset = 8;
  let hasHeader = false;
  let hasEnd = false;
  const compressed: Buffer[] = [];
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) throw new Error("Truncated PNG");
    const length = bytes.readUInt32BE(offset);
    const type = bytes.toString("ascii", offset + 4, offset + 8);
    const end = offset + 12 + length;
    if (end > bytes.length || (!hasHeader && type !== "IHDR"))
      throw new Error("Invalid PNG chunk");
    if (type === "IHDR") {
      if (hasHeader || length !== 13) throw new Error("Invalid PNG header");
      const width = bytes.readUInt32BE(offset + 8);
      const height = bytes.readUInt32BE(offset + 12);
      if (width === 0 || height === 0 || width * height > MAX_PIXELS)
        throw new Error("Oversized PNG");
      hasHeader = true;
    }
    if (type === "IDAT") compressed.push(bytes.subarray(offset + 8, end - 4));
    if (type === "IEND") {
      if (length !== 0 || end !== bytes.length)
        throw new Error("Invalid PNG ending");
      hasEnd = true;
    }
    offset = end;
  }
  if (!hasHeader || !hasEnd || compressed.length === 0)
    throw new Error("Incomplete PNG");
  inflateSync(Buffer.concat(compressed), { maxOutputLength: 16 * 1024 * 1024 });
}
