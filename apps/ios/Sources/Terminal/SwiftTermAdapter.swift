import Foundation
import SwiftTerm
import SwiftUI
import UIKit

@MainActor
protocol TerminalRendering: AnyObject {
    var onInput: ((Data) -> Void)? { get set }
    var onResize: ((Int, Int) -> Void)? { get set }
    var onLinkRequest: ((URL) -> Void)? { get set }
    var onTitleChange: ((String) -> Void)? { get set }

    func makeView() -> UIView
    func receiveOutput(_ data: Data)
    func resetForReplay()
    func focus()
    func armControlModifier()
    func armOptionModifier()
    func dismissKeyboard()
    func search(_ term: String, backwards: Bool) -> String
    func clearSearch()
}

@MainActor
final class SwiftTermAdapter: NSObject, TerminalRendering {
    var onInput: ((Data) -> Void)?
    var onResize: ((Int, Int) -> Void)?
    var onLinkRequest: ((URL) -> Void)?
    var onTitleChange: ((String) -> Void)?

    private let terminalView: TerminalView
    private var pinchStartFontSize: CGFloat = 13

    init(preferences: UserSettings? = nil) {
        let fontSize = CGFloat(min(max(preferences?.terminalFontSize ?? 13, 8), 48))
        terminalView = TerminalView(
            frame: .zero,
            font: UIFont.monospacedSystemFont(ofSize: fontSize, weight: .regular)
        )
        super.init()
        terminalView.terminalDelegate = self
        terminalView.linkReporting = .explicit
        terminalView.linkHighlightMode = .always
        terminalView.allowMouseReporting = false
        terminalView.caretViewTracksFocus = true
        terminalView.accessibilityLabel = "Remote terminal"
        terminalView.accessibilityHint = "Interactive remote terminal. Output may contain untrusted text."
        pinchStartFontSize = fontSize
        configureAppearance(
            theme: preferences?.terminalTheme ?? "system",
            cursorStyle: preferences?.terminalCursorStyle ?? "block"
        )
        terminalView.addGestureRecognizer(UIPinchGestureRecognizer(
            target: self,
            action: #selector(handlePinch(_:))
        ))
    }

    func makeView() -> UIView { terminalView }

    func receiveOutput(_ data: Data) {
        terminalView.feed(byteArray: Array(data)[...])
    }

    func resetForReplay() {
        let reset: [UInt8] = [0x1B, 0x63]
        terminalView.feed(byteArray: reset[...])
    }

    func focus() {
        terminalView.becomeFirstResponder()
    }

    func armControlModifier() {
        terminalView.controlModifier = true
        terminalView.becomeFirstResponder()
    }

    func armOptionModifier() {
        terminalView.metaModifier = true
        terminalView.becomeFirstResponder()
    }

    func dismissKeyboard() {
        terminalView.resignFirstResponder()
    }

    func search(_ term: String, backwards: Bool) -> String {
        guard !term.isEmpty else {
            terminalView.clearSearch()
            return ""
        }
        let found = backwards
            ? terminalView.findPrevious(term)
            : terminalView.findNext(term)
        let summary = terminalView.searchMatchSummary(term)
        return found ? "\(summary.index) of \(summary.total)" : "No matches"
    }

    func clearSearch() {
        terminalView.clearSearch()
    }

    private func configureAppearance(theme: String, cursorStyle: String) {
        let foreground: UIColor
        let background: UIColor
        let caret: UIColor
        switch theme {
        case "light":
            foreground = .black
            background = .white
            caret = .systemBlue
        case "high_contrast":
            foreground = .white
            background = .black
            caret = .systemYellow
        case "dark":
            foreground = .white
            background = .black
            caret = .systemCyan
        default:
            foreground = .label
            background = .systemBackground
            caret = .systemBlue
        }
        terminalView.nativeForegroundColor = foreground
        terminalView.nativeBackgroundColor = background
        terminalView.layer.backgroundColor = background.cgColor
        terminalView.caretColor = caret
        terminalView.caretTextColor = background
        terminalView.selectedTextBackgroundColor = UIColor.systemBlue.withAlphaComponent(0.45)

        let cursorSequence: [UInt8]
        switch cursorStyle {
        case "beam": cursorSequence = Array("\u{001B}[6 q".utf8)
        case "underline": cursorSequence = Array("\u{001B}[4 q".utf8)
        default: cursorSequence = Array("\u{001B}[2 q".utf8)
        }
        terminalView.feed(byteArray: cursorSequence[...])
    }

    @objc private func handlePinch(_ gesture: UIPinchGestureRecognizer) {
        if gesture.state == .began { pinchStartFontSize = terminalView.font.pointSize }
        guard gesture.state == .began || gesture.state == .changed else { return }
        let size = min(max(pinchStartFontSize * gesture.scale, 8), 48)
        terminalView.font = UIFont.monospacedSystemFont(ofSize: size, weight: .regular)
    }
}

// SwiftTerm 1.14.0 predates Swift 6 actor annotations. TerminalView invokes this
// UIKit delegate on the main thread, matching the adapter's isolation.
extension SwiftTermAdapter: @preconcurrency TerminalViewDelegate {
    func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
        guard newCols > 0, newRows > 0 else { return }
        onResize?(newCols, newRows)
    }

    func setTerminalTitle(source: TerminalView, title: String) {
        let sanitizedScalars = title.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
        }.prefix(128)
        onTitleChange?(String(sanitizedScalars.map(Character.init)))
    }

    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}

    func send(source: TerminalView, data: ArraySlice<UInt8>) {
        onInput?(Data(data))
    }

    func scrolled(source: TerminalView, position: Double) {}

    func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
        guard link.utf8.count <= 2_048,
              let url = URL(string: link),
              url.scheme?.lowercased() == "https",
              url.host != nil,
              url.user == nil,
              url.password == nil else { return }
        onLinkRequest?(url)
    }

    func bell(source: TerminalView) {
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    func clipboardCopy(source: TerminalView, content: Data) {
        // Remote OSC 52 clipboard writes are intentionally denied.
    }

    func clipboardRead(source: TerminalView) -> Data? {
        // Remote clipboard reads are intentionally denied.
        nil
    }

    func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
    func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
}

struct SwiftTermSurface: UIViewRepresentable {
    let adapter: SwiftTermAdapter

    func makeUIView(context: Context) -> UIView {
        adapter.makeView()
    }

    func updateUIView(_ uiView: UIView, context: Context) {}
}
