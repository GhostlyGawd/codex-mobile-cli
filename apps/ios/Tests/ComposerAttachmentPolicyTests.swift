import Foundation
import UniformTypeIdentifiers
import XCTest
@testable import CodexMobile

final class ComposerAttachmentPolicyTests: XCTestCase {
    func testDetectsAllowedTypesFromContent() throws {
        let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01])
        XCTAssertEqual(
            try ComposerAttachmentPolicy.mediaType(data: png, suggestedType: .png, fileName: "Screenshot.png"),
            "image/png"
        )
        XCTAssertEqual(
            try ComposerAttachmentPolicy.mediaType(
                data: Data(#"{"ok":true}"#.utf8), suggestedType: .json, fileName: "report.json"
            ),
            "application/json"
        )
        XCTAssertEqual(
            try ComposerAttachmentPolicy.mediaType(
                data: Data("let value = 1\n".utf8), suggestedType: UTType(filenameExtension: "swift"), fileName: "Example.swift"
            ),
            "text/plain"
        )
    }

    func testRejectsSpoofedAndExecutableContent() {
        XCTAssertThrowsError(try ComposerAttachmentPolicy.mediaType(
            data: Data("not actually png".utf8), suggestedType: .png, fileName: "fake.png"
        ))
        XCTAssertThrowsError(try ComposerAttachmentPolicy.mediaType(
            data: Data([0x4D, 0x5A, 0x00, 0x02]), suggestedType: nil, fileName: "program.exe"
        ))
        XCTAssertFalse(SensitivePathPolicy().permitsAttachment(name: ".env"))
        XCTAssertFalse(SensitivePathPolicy().permitsAttachment(name: "auth.json"))
        XCTAssertTrue(SensitivePathPolicy().permitsAttachment(name: "Example.swift"))
    }

    func testRejectsFileSizeLimit() {
        XCTAssertThrowsError(try ComposerAttachmentPolicy.mediaType(
            data: Data(repeating: 0x41, count: ComposerAttachmentPolicy.maximumFileBytes + 1),
            suggestedType: .plainText,
            fileName: "large.txt"
        ))
    }

    func testErrorEscapesHostileSelectedFilename() {
        XCTAssertThrowsError(try ComposerAttachmentPolicy.mediaType(
            data: Data(),
            suggestedType: .plainText,
            fileName: "safe.txt\u{202E}gpj\n"
        )) { error in
            XCTAssertEqual(
                error.localizedDescription,
                #"safe.txt\u{202E}gpj\u{000A} must be between one byte and five MiB."#
            )
        }
    }
}
