import Foundation
import XCTest
@testable import CodexMobile

final class JSONCodingContractTests: XCTestCase {
    func testWorkspaceAutonomyActionWireValue() throws {
        XCTAssertEqual(WorkspaceAction.updateAutonomy.rawValue, "update_autonomy")
        XCTAssertEqual(AutonomyMode.fullAccess.rawValue, "full_access")
    }

    func testAcronymKeysMatchOpenAPIExactly() throws {
        let share = ResourceShare(
            cpuCores: 1.5,
            memoryGiB: 3,
            writableDiskGiB: 12,
            pressure: .nominal
        )
        XCTAssertEqual(try keys(share), ["cpu_cores", "memory_gi_b", "pressure", "writable_disk_gi_b"])

        let workspace = NewWorkspaceRequest(
            repositoryID: "repo-1",
            initialPrompt: "Inspect the project",
            baseBranch: "main",
            taskName: "Contract test",
            autonomy: .balanced,
            nestedDocker: false,
            retention: .thirtyDays,
            environmentVariables: ["MY_VAR": "value"],
            requestedDiskGiB: 12
        )
        XCTAssertEqual(
            try keys(workspace),
            [
                "autonomy", "base_branch", "environment_variables", "initial_prompt", "nested_docker",
                "repository_id", "requested_disk_gi_b", "retention", "task_name"
            ]
        )
        let workspaceObject = try object(workspace)
        let environment = try XCTUnwrap(workspaceObject["environment_variables"] as? [String: String])
        XCTAssertEqual(environment, ["MY_VAR": "value"])
        let workspaceData = try JSONEncoder.codex.encode(workspace)
        XCTAssertEqual(try JSONDecoder.codex.decode(NewWorkspaceRequest.self, from: workspaceData), workspace)

        let save = SaveFileRequest(content: "text", expectedETag: "etag")
        XCTAssertEqual(try keys(save), ["content", "expected_e_tag"])

        let reorder = ReorderTerminalTabsRequest(tabIDs: ["tab-1", "tab-2"])
        XCTAssertEqual(try keys(reorder), ["tab_ids"])
        let close = CloseTerminalTabRequest(confirmed: true)
        XCTAssertEqual(try keys(close), ["confirmed"])
    }

    func testOpenAPISnakeCaseDecodesIntoAcronymProperties() throws {
        let json = Data(#"""
        {
          "cpu_cores": 2,
          "memory_gi_b": 4.5,
          "writable_disk_gi_b": 16,
          "pressure": "elevated"
        }
        """#.utf8)
        let share = try JSONDecoder.codex.decode(ResourceShare.self, from: json)
        XCTAssertEqual(share.memoryGiB, 4.5)
        XCTAssertEqual(share.writableDiskGiB, 16)
        XCTAssertEqual(share.pressure, .elevated)
    }

    func testIdentifierURLAndJSONAcronymsDecodeExactly() throws {
        let tokensJSON = Data(#"""
        {
          "access_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "access_expires_at": "2030-01-01T00:05:00Z",
          "refresh_token": "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr",
          "refresh_expires_at": "2030-02-01T00:00:00Z",
          "device_id": "device-1"
        }
        """#.utf8)
        let tokens = try JSONDecoder.codex.decode(SessionTokens.self, from: tokensJSON)
        XCTAssertEqual(tokens.deviceID, "device-1")

        let terminalJSON = Data(#"""
        {
          "websocket_url": "wss://api.example.test/v1/terminal",
          "connection_ticket": "tttttttttttttttttttttttttttttttt",
          "device_id": "device-1",
          "reconnect_token": null,
          "protocol_version": 1,
          "maximum_frame_bytes": 1048576,
          "lease_holder_device_id": "device-2"
        }
        """#.utf8)
        let terminal = try JSONDecoder.codex.decode(TerminalConnectionDescriptor.self, from: terminalJSON)
        XCTAssertEqual(terminal.websocketURL.absoluteString, "wss://api.example.test/v1/terminal")
        XCTAssertEqual(terminal.deviceID, "device-1")
        XCTAssertEqual(terminal.leaseHolderDeviceID, "device-2")

        let passkeyJSON = Data(#"""
        {
          "ceremony_id": "ceremony-1",
          "challenge": "YWJj",
          "relying_party_id": "codex.example.test",
          "allowed_credential_ids": ["ZGVm"]
        }
        """#.utf8)
        let passkey = try JSONDecoder.codex.decode(PasskeyAuthenticationChallenge.self, from: passkeyJSON)
        XCTAssertEqual(passkey.ceremonyID, "ceremony-1")
        XCTAssertEqual(passkey.relyingPartyID, "codex.example.test")
        XCTAssertEqual(passkey.allowedCredentialIDs, ["ZGVm"])

        let diffJSON = Data(#"""
        {
          "path": "Assets/icon.png",
          "unified_diff": null,
          "image_before_url": "https://api.example.test/v1/before",
          "image_after_url": "https://api.example.test/v1/after",
          "is_binary": true,
          "cache_directive": "never"
        }
        """#.utf8)
        let diff = try JSONDecoder.codex.decode(DiffDocument.self, from: diffJSON)
        XCTAssertEqual(diff.imageBeforeURL?.lastPathComponent, "before")
        XCTAssertEqual(diff.imageAfterURL?.lastPathComponent, "after")
    }

    func testPasskeyCredentialEncodingUsesWireAcronyms() throws {
        let credential = PasskeyRegistrationCredential(
            ceremonyID: "ceremony-1",
            credentialID: "Y3JlZGVudGlhbA",
            rawID: "cmF3",
            clientDataJSON: "Y2xpZW50",
            attestationObject: "YXR0ZXN0YXRpb24",
            deviceInstanceID: String(repeating: "a", count: 43),
            deviceName: "iPhone"
        )
        XCTAssertEqual(
            try keys(credential),
            [
                "attestation_object", "ceremony_id", "client_data_json", "credential_id",
                "device_instance_id", "device_name", "raw_id"
            ]
        )

        let challenge = PasskeyAuthenticationChallenge(
            ceremonyID: "ceremony-1",
            challenge: "YWJj",
            relyingPartyID: "codex.example.test",
            allowedCredentialIDs: ["ZGVm"]
        )
        XCTAssertEqual(
            try keys(challenge),
            ["allowed_credential_ids", "ceremony_id", "challenge", "relying_party_id"]
        )

        let metadataJSON = Data(#"""
        {
          "id": "Y3JlZGVudGlhbA",
          "device_name": "iPhone",
          "created_at": "2030-01-01T00:00:00Z"
        }
        """#.utf8)
        let metadata = try JSONDecoder.codex.decode(PasskeyMetadata.self, from: metadataJSON)
        XCTAssertEqual(metadata.id, "Y3JlZGVudGlhbA")
        XCTAssertEqual(metadata.deviceName, "iPhone")
        XCTAssertNil(metadata.lastUsedAt)
        XCTAssertEqual(try keys(metadata), ["created_at", "device_name", "id"])

        let usedMetadata = PasskeyMetadata(
            id: metadata.id,
            deviceName: metadata.deviceName,
            createdAt: metadata.createdAt,
            lastUsedAt: metadata.createdAt
        )
        XCTAssertEqual(try keys(usedMetadata), ["created_at", "device_name", "id", "last_used_at"])
    }

    func testPushEnvironmentUsesContractVocabulary() throws {
        let registration = PushDeviceRegistration(
            token: String(repeating: "a", count: 64),
            environment: "sandbox",
            locale: "en_US"
        )
        let object = try object(registration)
        XCTAssertEqual(object["environment"] as? String, "sandbox")
    }

    func testAttachmentBytesUseBoundedBase64WireField() throws {
        let request = StageAttachmentsRequest(attachments: [
            AttachmentUpload(mediaType: "text/plain", contentBase64: Data("hello".utf8))
        ])
        XCTAssertEqual(try keys(request), ["attachments"])
        let requestObject = try object(request)
        let attachments = try XCTUnwrap(requestObject["attachments"] as? [[String: Any]])
        XCTAssertEqual(attachments.first?["media_type"] as? String, "text/plain")
        XCTAssertEqual(attachments.first?["content_base64"] as? String, "aGVsbG8=")

        let response = Data(#"""
        {
          "attachments": [{
            "id": "att_abcdefghijklmnopqrstuvwx",
            "path": "/codex-mobile-attachments/stage-1784205000-abcdefghijklmnop/att_abcdefghijklmnopqrstuvwx.txt",
            "media_type": "text/plain",
            "size_bytes": 5,
            "expires_at": "2026-07-16T12:30:00Z"
          }]
        }
        """#.utf8)
        let decoded = try JSONDecoder.codex.decode(StageAttachmentsResult.self, from: response)
        XCTAssertEqual(decoded.attachments.first?.sizeBytes, 5)
    }

    func testSecretRequestsEncodeScopeButMetadataHasNoValue() throws {
        let request = CreateSecretRequest(name: "DEPLOY_TOKEN", value: "transient-value", repositoryID: "repo-1")
        XCTAssertEqual(try keys(request), ["name", "repository_id", "value"])

        let metadataJSON = Data(#"""
        {
          "id": "secret-1",
          "name": "DEPLOY_TOKEN",
          "scope": "repository",
          "repository_id": "repo-1",
          "value_bytes": 15,
          "created_at": "2030-01-01T00:00:00Z",
          "updated_at": "2030-01-02T00:00:00Z"
        }
        """#.utf8)
        let metadata = try JSONDecoder.codex.decode(SecretMetadata.self, from: metadataJSON)
        XCTAssertEqual(metadata.repositoryID, "repo-1")
        XCTAssertEqual(try keys(metadata), ["created_at", "id", "name", "repository_id", "scope", "updated_at", "value_bytes"])
    }

    func testConnectionStatusUsesOpenAPIWireKeysAndStates() throws {
        let response = Data(#"""
        {
          "github": {
            "configured": true,
            "connected": true,
            "installations": [{
              "installation_id": 42,
              "account_login": "owner",
              "account_type": "User",
              "repository_selection": "selected",
              "updated_at": "2030-01-01T00:00:00Z"
            }]
          },
          "codex": {
            "scope": "per_workspace",
            "connected_workspace_count": 1,
            "authenticating_workspace_count": 0,
            "disconnected_workspace_count": 0,
            "unavailable_workspace_count": 0,
            "workspaces": [{
              "workspace_id": "ws-one",
              "workspace_name": "One",
              "state": "connected",
              "checked_at": "2030-01-01T00:00:00Z"
            }]
          }
        }
        """#.utf8)

        let status = try JSONDecoder.codex.decode(ConnectionStatus.self, from: response)
        XCTAssertEqual(status.github.installations.first?.installationID, 42)
        XCTAssertEqual(status.codex.scope, "per_workspace")
        XCTAssertEqual(status.codex.workspaces.first?.state, .connected)
        XCTAssertEqual(
            try keys(ConfirmConnectionDisconnectRequest(confirmed: true)),
            ["confirmed"]
        )
    }

    func testBase64URLDecoderRejectsNonContractAlphabet() {
        XCTAssertNotNil(Data(base64URLEncoded: "YWJj"))
        XCTAssertNil(Data(base64URLEncoded: "YWJj+g"))
        XCTAssertNil(Data(base64URLEncoded: "YWJj="))
        XCTAssertNil(Data(base64URLEncoded: ""))
    }

    private func keys<T: Encodable>(_ value: T) throws -> [String] {
        try object(value).keys.sorted()
    }

    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        let data = try JSONEncoder.codex.encode(value)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}
