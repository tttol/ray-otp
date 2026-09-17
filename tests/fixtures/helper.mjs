#!/usr/bin/env node
// Synthetic subprocess protocol fixture. Never touches Keychain.
let input = "";
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
switch (request.keyId.slice(0, 8)) {
  case "00000001":
    process.stdout.write(
      JSON.stringify({ key: Buffer.alloc(32, 7).toString("base64") }),
    );
    break;
  case "00000002":
    process.stdout.write('{"error":"cancelled"}');
    process.exitCode = 1;
    break;
  case "00000003":
    process.stdout.write("{invalid");
    break;
  case "00000004":
    process.stdout.write("x".repeat(5000));
    break;
  case "00000005":
    setInterval(() => {}, 1000);
    break;
  default:
    process.stdout.write('{"error":"denied"}');
    process.exitCode = 1;
}
