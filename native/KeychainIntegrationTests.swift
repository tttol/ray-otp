import Foundation
import Security

func require(_ condition: Bool, _ message: String) {
    guard condition else { fatalError(message) }
}
func checked(_ status: OSStatus, _ operation: String) {
    require(status == errSecSuccess, "\(operation) failed with status \(status)")
}

guard CommandLine.arguments.count == 3 else { fatalError("Expected test helper and temporary directory") }
let helper = CommandLine.arguments[1]
let directory = CommandLine.arguments[2]
let keychainPath = directory + "/synthetic.keychain-db"
let password = UUID().uuidString
var keychain: SecKeychain?
checked(SecKeychainCreate(keychainPath, UInt32(password.utf8.count), password, false, nil, &keychain), "Create isolated Keychain")
guard let keychain else { fatalError("Missing Keychain") }
defer { _ = SecKeychainDelete(keychain) }
checked(SecKeychainUnlock(keychain, UInt32(password.utf8.count), password, true), "Unlock isolated Keychain")

func run(_ operation: String, _ id: String) -> [String: String] {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: helper)
    process.arguments = [keychainPath]
    let input = Pipe()
    let output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    try! process.run()
    input.fileHandleForWriting.write(try! JSONSerialization.data(withJSONObject: ["operation": operation, "keyId": id]))
    try! input.fileHandleForWriting.close()
    let bytes = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (try? JSONSerialization.jsonObject(with: bytes)) as? [String: String] ?? [:]
}

let id = UUID().uuidString.lowercased()
let created = run("create", id)
require(created["key"].flatMap { Data(base64Encoded: $0) }?.count == 32, "Create must return a 32-byte key")
require(run("read", id) == created, "Fresh helper processes must retrieve the same key")
require(run("create", id)["error"] == "duplicate", "Duplicate creation must not replace keys")
require(run("read", UUID().uuidString)["error"] == "missing", "Missing keys must be explicit")
require(run("delete", id)["error"] == "invalid-request", "Unsupported operations must be rejected")
require(run("read", "invalid")["error"] == "invalid-request", "Invalid IDs must be rejected")

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "ray-otp",
    kSecAttrAccount as String: id,
    kSecMatchSearchList as String: [keychain],
    kSecReturnRef as String: true,
]
var item: CFTypeRef?
checked(SecItemCopyMatching(query as CFDictionary, &item), "Find test item")
var access: SecAccess?
checked(SecKeychainItemCopyAccess(item as! SecKeychainItem, &access), "Read ACL")
var aclList: CFArray?
checked(SecAccessCopyACLList(access!, &aclList), "Read ACL entries")
let decryptEntries = (aclList as! [SecACL]).filter {
    (SecACLCopyAuthorizations($0) as! [String]).contains(kSecACLAuthorizationDecrypt as String)
}
require(!decryptEntries.isEmpty, "Expected decrypt ACL")
for acl in decryptEntries {
    var applications: CFArray?
    var description: CFString?
    var selector = SecKeychainPromptSelector(rawValue: 0)
    checked(SecACLCopyContents(acl, &applications, &description, &selector), "Read trusted applications")
    require(applications != nil && CFArrayGetCount(applications!) == 1, "Exactly the creating helper must be trusted")
}

checked(SecKeychainLock(keychain), "Lock isolated Keychain")
let lockedResponse = run("read", id)
require(lockedResponse["key"] == nil, "Locked Keychain must not return a key")
require(["locked", "denied"].contains(lockedResponse["error"] ?? ""), "Locked Keychain error: \(lockedResponse["error"] ?? "none")")
checked(SecKeychainUnlock(keychain, UInt32(password.utf8.count), password, true), "Unlock isolated Keychain")
require(run("read", id) == created, "Unlock must restore access")
print("Keychain integration passed: create, restart read, duplicate, missing, validation, ACL, lock/unlock.")
