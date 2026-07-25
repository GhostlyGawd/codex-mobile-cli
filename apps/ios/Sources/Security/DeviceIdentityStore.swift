import Foundation
import Security

actor DeviceIdentityStore {
    private let keychain: KeychainStore
    private let account = "device-instance-v1"

    init(keychain: KeychainStore = KeychainStore()) {
        self.keychain = keychain
    }

    func identity(deviceName: String) throws -> DeviceIdentityRequest {
        let data: Data
        if let stored = try keychain.data(for: account) {
            guard stored.count == 32 else { throw KeychainError.invalidData }
            data = stored
        } else {
            var generated = Data(count: 32)
            let status = generated.withUnsafeMutableBytes { bytes in
                SecRandomCopyBytes(kSecRandomDefault, 32, bytes.baseAddress!)
            }
            guard status == errSecSuccess else { throw KeychainError.status(status) }
            try keychain.set(generated, for: account)
            data = generated
        }
        return DeviceIdentityRequest(
            deviceInstanceID: data.base64URLEncodedString,
            deviceName: deviceName
        )
    }
}
