import Foundation

struct PreviewOriginPolicy: Equatable, Sendable {
    let allowedHost: String
    let allowedPort: Int

    func permits(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https"
            && url.host?.lowercased() == allowedHost.lowercased()
            && (url.port ?? 443) == allowedPort
            && url.user == nil
            && url.password == nil
    }
}
