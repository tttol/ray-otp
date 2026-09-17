# ray-otp

`ray-otp` is a local-only Raycast extension for generating six-digit TOTP codes.

## Privacy model

- TOTP codes are calculated on this Mac with Node's built-in HMAC implementation.
- The extension contains no runtime network requests, analytics, remote icons, cloud sync, or AI tools.
- Secrets are stored in an encrypted vault at `~/Library/Application Support/ray-otp`.
- A random 256-bit encryption key is stored under service `ray-otp` in the local login Keychain. It is not synchronized through iCloud. The vault file never contains the key.
- Fresh command launches unlock automatically when macOS permits Keychain access. macOS may request authorization or a Keychain password; there is no routine application master-password prompt.
- A small, locally built Swift helper accesses Keychain through Apple's Security framework. All other application code remains TypeScript. Key material passes over private process pipes, never command arguments or logs.
- Copied codes use Raycast's confidential clipboard option, so Raycast Clipboard History does not record them. macOS Universal Clipboard may still share clipboard content if it is enabled in System Settings.

Raycast extensions are not OS-level network sandboxes. This extension intentionally contains no code that calls a network API, but Raycast and macOS remain trusted components.

The helper's Keychain access list trusts the creating executable, not every application. However, another process running as your macOS user can invoke that helper. Automatic unlock is not strong isolation from malicious software in your user session. JavaScript strings and runtime copies cannot be guaranteed to be securely erased; locking clears application references and wipes owned key buffers.

## Using Keychain

Open **Show OTP Codes**. A new installation creates an encrypted empty vault and its Keychain item automatically. Add accounts as usual; Enter copies a freshly generated code and shows **Copied!**.

For an existing password-protected vault, **Migrate to Mac Keychain** asks for the old master password once. Enter it directly in Raycast. The extension validates the old vault, creates and reads back a Keychain key, preserves an exact encrypted backup as `vault.pre-keychain.json`, then atomically replaces `vault.json`. Account IDs, settings, and icons are retained. The old password is never stored.

**Lock Vault** and five minutes of inactivity clear the current session and any open account form. Select **Unlock with Keychain** to return. A fresh command launch unlocks automatically. Locking hides data and clears memory; it does not lock your system Keychain or require Touch ID.

If access fails or is cancelled, choose **Retry** after resolving it in Keychain Access. A missing key never causes an existing vault to be reset. Do not delete its Keychain item. A failed initialization or interrupted migration can leave an unused `ray-otp` Keychain item; these are intentionally retained rather than risking deletion of a committed vault's key.

## Local development

Use Node.js 22.22.2 or newer for the pinned Raycast API dependency, plus Xcode or Command Line Tools with a macOS SDK and Swift compiler.

```bash
npm install
npm run dev
```

The extension is registered in Raycast's development section. Stop the development process with `Ctrl+C`; the last local build remains installed in Raycast. Run `npm run dev` again after changing the source.

Both `npm run dev` and `npm run build` prepare the Swift helper for the current Mac architecture and ad-hoc sign it. Unchanged source, build configuration, and compiler reuse the existing signed binary. Changing or moving the helper may cause macOS to ask for authorization again. The file-based login Keychain uses legacy Apple APIs, so deprecation warnings during compilation are expected. No paid signing certificate or third-party native package is required.

Run validation and tests with:

```bash
npm run test
npm run lint
npm run build
npm run test:keychain
```

The regular tests use synthetic data and a fake key store. `test:keychain` compiles a separate test-only helper, creates a temporary Keychain, tests actual access controls and lock/unlock, and removes it. It does not read or write production keys. Production helper builds accept no Keychain path override.

## Manual backup

To back up the vault, copy the complete directory below while the extension is locked:

```text
~/Library/Application Support/ray-otp
```

The backup contains encrypted data and ordinary local icon files, and remains sensitive. A version-2 vault requires its matching Keychain item: copying this directory alone cannot recover the vault after losing or replacing the Keychain. There is no key export or recovery UI. Retain provider recovery codes separately.

`vault.pre-keychain.json` is the original migration snapshot. It remains protected by the old master password and contains only the accounts/settings present at migration; later changes are not included. Keep that password if you retain this backup. To restore the legacy snapshot manually, first preserve the current directory, close the command, replace `vault.json` with the snapshot, and open the command to migrate again. Preserve a differing existing migration backup elsewhere before retrying; the extension will never overwrite it.

## Current limits

The first version supports manual Base32 secret entry, six-digit TOTP, configurable periods and hash algorithms, and manually selected local icons. Secrets accept case/spacing normalization and optional canonical Base32 padding; malformed padding and nonzero unused bits are rejected. QR scanning, `otpauth://` import, HOTP, and graphical backup/restore are intentionally deferred.

Custom PNG/JPEG icons must be at most 1 MiB and one megapixel. Pinned JavaScript decoders (`pngjs` and `jpeg-js`) validate them locally with bounded input and decompression before the exact validated bytes are saved. No images are uploaded. Invalid or unsupported images are rejected; resize larger images before importing. A failed cleanup reports an unused local icon rather than hiding an account-save error or deleting an icon referenced by a saved account.

For source audits: `jpeg-js` contains an unused internal browser URL-loading method. This extension calls only its synchronous byte-buffer decoder, which calls the parser directly; it never calls that loader or supplies a URL. The decoder's internal image object is not exposed by that API. This is a code-path restriction, not an OS-enforced network sandbox.
