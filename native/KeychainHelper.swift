import Foundation
import Security

// The helper intentionally exposes only this application's key namespace.
let service = "ray-otp"
let inputLimit = 4096

struct Request: Decodable {
    let operation: String
    let keyId: String
}

func fail(_ code: String) -> Never {
    let response = try! JSONSerialization.data(withJSONObject: ["error": code])
    FileHandle.standardOutput.write(response)
    exit(1)
}

func check(_ status: OSStatus) {
    switch status {
    case errSecSuccess: return
    case errSecItemNotFound: fail("missing")
    case errSecUserCanceled: fail("cancelled")
    case errSecAuthFailed: fail("denied")
    case errSecInteractionNotAllowed: fail("locked")
    case errSecDuplicateItem: fail("duplicate")
    default: fail("unavailable")
    }
}

var input = Data()
while let chunk = try? FileHandle.standardInput.read(upToCount: inputLimit + 1), !chunk.isEmpty {
    input.append(chunk)
    if input.count > inputLimit { fail("invalid-request") }
}
guard let request = try? JSONDecoder().decode(Request.self, from: input),
      let uuid = UUID(uuidString: request.keyId),
      uuid.uuidString.lowercased() == request.keyId.lowercased(),
      ["create", "read"].contains(request.operation) else { fail("invalid-request") }

var keychain: SecKeychain?
#if KEYCHAIN_TEST
// Compiled only into the isolated test binary; production accepts no path override.
guard CommandLine.arguments.count == 2 else { fail("invalid-request") }
let keychainPath = CommandLine.arguments[1]
check(SecKeychainSetUserInteractionAllowed(false))
#else
guard CommandLine.arguments.count == 1 else { fail("invalid-request") }
let keychainPath = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Keychains/login.keychain-db").path
#endif
check(SecKeychainOpen(keychainPath, &keychain))
guard let keychain else { fail("unavailable") }

let keyId = uuid.uuidString.lowercased()
let identity: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: keyId,
]

if request.operation == "create" {
    var key = Data(count: 32)
    let randomStatus = key.withUnsafeMutableBytes { bytes in
        SecRandomCopyBytes(kSecRandomDefault, 32, bytes.baseAddress!)
    }
    check(randomStatus)
    defer { key.resetBytes(in: 0..<key.count) }
    // NULL means only the creating executable is trusted, NOT all applications.
    var access: SecAccess?
    check(SecAccessCreate("ray-otp Vault Key" as CFString, nil, &access))
    guard let access else { fail("unavailable") }
    var attributes = identity
    attributes[kSecUseKeychain as String] = keychain
    attributes[kSecAttrAccess as String] = access
    attributes[kSecAttrLabel as String] = "ray-otp Vault Key"
    attributes[kSecValueData as String] = key
    check(SecItemAdd(attributes as CFDictionary, nil))
}

var query = identity
query[kSecMatchSearchList as String] = [keychain]
query[kSecMatchLimit as String] = kSecMatchLimitOne
query[kSecReturnData as String] = true
var result: CFTypeRef?
check(SecItemCopyMatching(query as CFDictionary, &result))
guard var key = result as? Data, key.count == 32 else { fail("unavailable") }
defer { key.resetBytes(in: 0..<key.count) }
guard let response = try? JSONSerialization.data(withJSONObject: ["key": key.base64EncodedString()]) else {
    fail("unavailable")
}
FileHandle.standardOutput.write(response)
