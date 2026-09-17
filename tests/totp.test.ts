import assert from "node:assert/strict";
import test from "node:test";
import {
  decodeBase32,
  generateTotp,
  getRemainingSeconds,
  normalizeBase32Secret,
  validatePeriod,
} from "../src/totp";

// RFC 6238 Appendix A uses 20-, 32-, and 64-byte ASCII secrets respectively.
// Expected values are the six-digit suffixes of Appendix B's eight-digit vectors.
// Source: https://www.rfc-editor.org/rfc/rfc6238.txt
const vectors = [
  {
    algorithm: "sha1",
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    codes: ["287082", "081804", "050471", "005924", "279037", "353130"],
  },
  {
    algorithm: "sha256",
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
    codes: ["119246", "084774", "062674", "819424", "698825", "737706"],
  },
  {
    algorithm: "sha512",
    secret:
      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
    codes: ["693936", "091201", "943326", "441116", "618901", "863826"],
  },
] as const;
const timestamps = [
  59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000,
  20_000_000_000,
] as const;

for (const vector of vectors) {
  for (const [index, seconds] of timestamps.entries()) {
    test(`generateTotp matches RFC 6238 ${vector.algorithm} at ${seconds}s`, () => {
      // Given
      const expected = vector.codes[index];
      const options = { period: 30, algorithm: vector.algorithm };
      // When
      const actual = generateTotp(vector.secret, seconds * 1000, options);
      // Then
      assert.equal(actual, expected);
    });
  }
}

for (const [timestamp, period, expected] of [
  [0, 30, "755224"],
  [29_999, 30, "755224"],
  [30_000, 30, "287082"],
  [59_999, 60, "755224"],
  [60_000, 60, "287082"],
  [119_999, 60, "287082"],
] as const) {
  test(`generateTotp handles rollover at ${timestamp}ms with period ${period}`, () => {
    // Given
    const secret = vectors[0].secret;
    const options = { period, algorithm: "sha1" } as const;
    // When
    const actual = generateTotp(secret, timestamp, options);
    // Then
    assert.equal(actual, expected);
  });
}

test("generateTotp follows a backward clock jump without cached codes", () => {
  // Given
  const options = { period: 30, algorithm: "sha1" } as const;
  generateTotp(vectors[0].secret, 30_000, options);
  const expected = "755224";
  // When
  const actual = generateTotp(vectors[0].secret, 29_999, options);
  // Then
  assert.equal(actual, expected);
});

for (const [input, expected] of [
  [" my====== \n", "MY"],
  ["MY", "MY"],
  ["MZXQ====", "MZXQ"],
  ["MZXW6===", "MZXW6"],
  ["MZXW6YQ=", "MZXW6YQ"],
  ["MZXW6YTB", "MZXW6YTB"],
  [" gezd gnbv-gy3t qojq ", "GEZDGNBVGY3TQOJQ"],
] as const) {
  test(`normalizeBase32Secret accepts ${JSON.stringify(input)}`, () => {
    // Given: parameterized input and canonical expected value.
    // When
    const actual = normalizeBase32Secret(input);
    // Then
    assert.equal(actual, expected);
  });
}

for (const input of [
  "",
  "A",
  "AAA",
  "AAAAAA",
  "not-valid-0",
  "M=Y",
  "MY=",
  "MY=======",
  "MZXW6YTB=",
  "MZ",
  "MZ======",
  "MZXR",
  "MZXW7",
  "MZXW6YR",
]) {
  test(`normalizeBase32Secret rejects malformed ${JSON.stringify(input)}`, () => {
    // Given
    const expected = /OTP secret/;
    // When
    const actual = () => normalizeBase32Secret(input);
    // Then
    assert.throws(actual, expected);
  });
}

for (const [input, text] of [
  ["MY======", "f"],
  ["MZXQ", "fo"],
  ["MZXW6", "foo"],
  ["MZXW6YQ", "foob"],
  ["MZXW6YTB", "fooba"],
] as const) {
  test(`decodeBase32 decodes ${input}`, () => {
    // Given
    const expected = Buffer.from(text);
    // When
    const actual = decodeBase32(input);
    // Then
    assert.deepEqual(actual, expected);
  });
}

for (const [timestamp, period, expected] of [
  [0, 30, 30],
  [29_999, 30, 1],
  [30_000, 30, 30],
  [60_000, 60, 60],
] as const) {
  test(`getRemainingSeconds handles ${timestamp}ms and period ${period}`, () => {
    // Given: parameterized timestamp, period, and expected seconds.
    // When
    const actual = getRemainingSeconds(timestamp, period);
    // Then
    assert.equal(actual, expected);
  });
}

for (const period of [0, -1, 0.5, 86401, NaN, Infinity]) {
  test(`validatePeriod rejects ${period}`, () => {
    // Given
    const expected = /period/;
    // When
    const actual = () => validatePeriod(period);
    // Then
    assert.throws(actual, expected);
  });
}

for (const period of [1, 30, 60, 86400]) {
  test(`validatePeriod accepts ${period}`, () => {
    // Given
    const expected = period;
    // When
    const actual = validatePeriod(period);
    // Then
    assert.equal(actual, expected);
  });
}
