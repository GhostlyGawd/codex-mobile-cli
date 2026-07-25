import AuthenticationServices
import Foundation
import UIKit

@MainActor
protocol PasskeyPerforming: AnyObject {
    func register(_ challenge: PasskeyRegistrationChallenge, identity: DeviceIdentityRequest) async throws -> PasskeyRegistrationCredential
    func authenticate(_ challenge: PasskeyAuthenticationChallenge, identity: DeviceIdentityRequest) async throws -> PasskeyAssertionCredential
}

@MainActor
final class PlatformPasskeyClient: NSObject, PasskeyPerforming {
    private enum CeremonyResult {
        case registration(PasskeyRegistrationCredential)
        case assertion(PasskeyAssertionCredential)
    }

    private let expectedRelyingPartyID: String
    private var continuation: CheckedContinuation<CeremonyResult, Error>?
    private var ceremonyID: String?
    private var deviceIdentity: DeviceIdentityRequest?
    private var authorizationController: ASAuthorizationController?

    init(expectedRelyingPartyID: String) {
        self.expectedRelyingPartyID = expectedRelyingPartyID
        super.init()
    }

    func register(_ challenge: PasskeyRegistrationChallenge, identity: DeviceIdentityRequest) async throws -> PasskeyRegistrationCredential {
        try validate(relyingPartyID: challenge.relyingPartyID)
        guard let challengeData = Data(base64URLEncoded: challenge.challenge),
              let userID = Data(base64URLEncoded: challenge.userID) else {
            throw ClientError.malformedData("The passkey registration challenge was malformed.")
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: challenge.relyingPartyID
        )
        let request = provider.createCredentialRegistrationRequest(
            challenge: challengeData,
            name: challenge.userName,
            userID: userID
        )
        request.displayName = challenge.userDisplayName
        request.userVerificationPreference = .required
        let excludedCredentials = challenge.excludedCredentialIDs.compactMap {
            Data(base64URLEncoded: $0).map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
            }
        }
        guard excludedCredentials.count == challenge.excludedCredentialIDs.count else {
            throw ClientError.malformedData("The passkey exclusion list was malformed.")
        }
        request.excludedCredentials = excludedCredentials

        let result = try await perform(request: request, ceremonyID: challenge.ceremonyID, identity: identity)
        guard case let .registration(credential) = result else {
            throw ClientError.invalidResponse
        }
        return credential
    }

    func authenticate(_ challenge: PasskeyAuthenticationChallenge, identity: DeviceIdentityRequest) async throws -> PasskeyAssertionCredential {
        try validate(relyingPartyID: challenge.relyingPartyID)
        guard let challengeData = Data(base64URLEncoded: challenge.challenge) else {
            throw ClientError.malformedData("The passkey authentication challenge was malformed.")
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: challenge.relyingPartyID
        )
        let request = provider.createCredentialAssertionRequest(challenge: challengeData)
        request.userVerificationPreference = .required
        let allowedCredentials = challenge.allowedCredentialIDs.compactMap {
            Data(base64URLEncoded: $0).map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
            }
        }
        guard allowedCredentials.count == challenge.allowedCredentialIDs.count else {
            throw ClientError.malformedData("The allowed passkey list was malformed.")
        }
        request.allowedCredentials = allowedCredentials

        let result = try await perform(request: request, ceremonyID: challenge.ceremonyID, identity: identity)
        guard case let .assertion(credential) = result else {
            throw ClientError.invalidResponse
        }
        return credential
    }

    private func perform(
        request: ASAuthorizationRequest,
        ceremonyID: String,
        identity: DeviceIdentityRequest
    ) async throws -> CeremonyResult {
        guard continuation == nil else {
            throw ClientError.conflict("Another passkey ceremony is already in progress.")
        }
        self.ceremonyID = ceremonyID
        self.deviceIdentity = identity
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            self.authorizationController = controller
            controller.performRequests()
        }
    }

    private func validate(relyingPartyID: String) throws {
        guard relyingPartyID.lowercased() == expectedRelyingPartyID.lowercased(),
              !relyingPartyID.lowercased().hasSuffix(".invalid") else {
            throw ClientError.forbidden("The server passkey relying-party ID does not match this signed app.")
        }
    }

    private func finish(_ result: Result<CeremonyResult, Error>) {
        let pending = continuation
        continuation = nil
        ceremonyID = nil
        deviceIdentity = nil
        authorizationController = nil
        pending?.resume(with: result)
    }
}

extension PlatformPasskeyClient: ASAuthorizationControllerDelegate {
    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard let ceremonyID, let deviceIdentity else {
            finish(.failure(ClientError.invalidResponse))
            return
        }
        if let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
           let attestation = registration.rawAttestationObject {
            let credential = PasskeyRegistrationCredential(
                ceremonyID: ceremonyID,
                credentialID: registration.credentialID.base64URLEncodedString,
                rawID: registration.credentialID.base64URLEncodedString,
                clientDataJSON: registration.rawClientDataJSON.base64URLEncodedString,
                attestationObject: attestation.base64URLEncodedString,
                deviceInstanceID: deviceIdentity.deviceInstanceID,
                deviceName: deviceIdentity.deviceName
            )
            finish(.success(.registration(credential)))
            return
        }
        if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            let credential = PasskeyAssertionCredential(
                ceremonyID: ceremonyID,
                credentialID: assertion.credentialID.base64URLEncodedString,
                rawID: assertion.credentialID.base64URLEncodedString,
                clientDataJSON: assertion.rawClientDataJSON.base64URLEncodedString,
                authenticatorData: assertion.rawAuthenticatorData.base64URLEncodedString,
                signature: assertion.signature.base64URLEncodedString,
                userHandle: assertion.userID.isEmpty ? nil : assertion.userID.base64URLEncodedString,
                deviceInstanceID: deviceIdentity.deviceInstanceID,
                deviceName: deviceIdentity.deviceName
            )
            finish(.success(.assertion(credential)))
            return
        }
        finish(.failure(ClientError.invalidResponse))
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        finish(.failure(error))
    }
}

extension PlatformPasskeyClient: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        if let window = scenes.flatMap(\.windows).first(where: \.isKeyWindow) ?? scenes.first?.windows.first {
            return window
        }
        return ASPresentationAnchor(frame: UIScreen.main.bounds)
    }
}

@MainActor
final class PasskeyAuthService {
    private let api: any CodexMobileAPI
    private let performer: any PasskeyPerforming
    private let sessionStore: SessionStore
    private let deviceIdentityStore: DeviceIdentityStore

    init(
        api: any CodexMobileAPI,
        performer: any PasskeyPerforming,
        sessionStore: SessionStore,
        deviceIdentityStore: DeviceIdentityStore = DeviceIdentityStore()
    ) {
        self.api = api
        self.performer = performer
        self.sessionStore = sessionStore
        self.deviceIdentityStore = deviceIdentityStore
    }

    func registerFirstPasskey(bootstrapToken: String) async throws -> SessionTokens {
        let identity = try await deviceIdentityStore.identity(deviceName: genericDeviceName)
        let options = try await api.beginPasskeyRegistration(BootstrapRegistrationRequest(
            bootstrapToken: bootstrapToken,
            deviceInstanceID: identity.deviceInstanceID,
            deviceName: identity.deviceName
        ))
        let credential = try await performer.register(options, identity: identity)
        let session = try await api.finishPasskeyRegistration(credential)
        try await sessionStore.save(session)
        return session
    }

    func authenticate() async throws -> SessionTokens {
        let identity = try await deviceIdentityStore.identity(deviceName: genericDeviceName)
        let options = try await api.beginPasskeyAuthentication(identity)
        let credential = try await performer.authenticate(options, identity: identity)
        let session = try await api.finishPasskeyAuthentication(credential)
        try await sessionStore.save(session)
        return session
    }

    func registerAdditionalPasskey() async throws -> PasskeyMetadata {
        let identity = try await deviceIdentityStore.identity(deviceName: genericDeviceName)
        let options = try await api.beginAdditionalPasskeyRegistration(identity)
        let credential = try await performer.register(options, identity: identity)
        return try await api.finishAdditionalPasskeyRegistration(credential)
    }

    private var genericDeviceName: String {
        UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
    }
}
