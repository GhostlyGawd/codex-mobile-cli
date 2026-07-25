import Foundation

enum AppDisplayName {
    static let value: String = {
        let configured = Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
        let trimmed = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? "Codex Mobile" : trimmed
    }()
}
