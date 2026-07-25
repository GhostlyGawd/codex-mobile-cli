import Foundation

struct SensitivePathPolicy: Sendable {
    private let deniedComponents: Set<String> = [
        ".ssh", ".aws", ".azure", ".gnupg", ".codex", ".docker", ".git", ".kube",
        ".terraform", ".terraform.d",
        "secrets", "credentials", "credential", "tokens", "private_keys"
    ]
    private let deniedNames: Set<String> = [
        ".env", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".gitconfig",
        "auth.json", "credentials.json", "service-account.json", "id_rsa", "id_ed25519",
        "kubeconfig", "terraform.tfstate", "terraform.tfstate.backup"
    ]
    private let deniedExtensions: Set<String> = [
        "pem", "p8", "p12", "pfx", "key", "keystore", "mobileprovision"
    ]

    func permitsCaching(path: String) -> Bool {
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.hasPrefix("\\"),
              !path.contains("\0") else { return false }

        let normalized = path.replacingOccurrences(of: "\\", with: "/")
        let components = normalized.split(separator: "/", omittingEmptySubsequences: false).map {
            String($0).lowercased()
        }
        guard !components.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else { return false }
        guard !components.contains(where: deniedComponents.contains) else { return false }

        guard let filename = components.last else { return false }
        if deniedNames.contains(filename) || filename.hasPrefix(".env.") { return false }
        if filename.contains("secret") || filename.contains("credential") || filename.hasSuffix("token") { return false }
        if let fileExtension = filename.split(separator: ".").last.map(String.init),
           deniedExtensions.contains(fileExtension) { return false }

        if let configIndex = components.firstIndex(of: ".config"),
           components.indices.contains(configIndex + 1),
           ["gh", "gcloud", "op", "1password"].contains(components[configIndex + 1]) {
            return false
        }
        return true
    }

    func permitsAttachment(name: String) -> Bool {
        guard !name.contains("/"), !name.contains("\\") else { return false }
        return permitsCaching(path: name)
    }
}
