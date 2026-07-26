import Foundation
import Runestone
import SwiftUI
import TreeSitterBashRunestone
import TreeSitterCSSRunestone
import TreeSitterGoRunestone
import TreeSitterHTMLRunestone
import TreeSitterJavaScriptRunestone
import TreeSitterJSONRunestone
import TreeSitterMarkdownRunestone
import TreeSitterPythonRunestone
import TreeSitterSwiftRunestone
import TreeSitterTOMLRunestone
import TreeSitterTSXRunestone
import TreeSitterTypeScriptRunestone
import TreeSitterYAMLRunestone
import UIKit

@MainActor
protocol TextEditing: AnyObject {
    var onTextChange: ((String) -> Void)? { get set }
    var text: String { get }
    func makeView() -> UIView
    func load(_ document: FileDocument)
    func setEditable(_ editable: Bool)
}

@MainActor
final class RunestoneAdapter: NSObject, TextEditing {
    var onTextChange: ((String) -> Void)?

    private let textView = TextView(frame: .zero)
    private var loadedETag: String?
    private var applyingState = false

    override init() {
        super.init()
        textView.editorDelegate = self
        textView.showLineNumbers = true
        textView.lineSelectionDisplayType = .line
        textView.isLineWrappingEnabled = false
        textView.isFindInteractionEnabled = true
        textView.autocorrectionType = .no
        textView.autocapitalizationType = .none
        textView.smartQuotesType = .no
        textView.smartDashesType = .no
        textView.spellCheckingType = .no
        textView.accessibilityLabel = "Code editor"
        textView.accessibilityTextualContext = .sourceCode
    }

    var text: String { textView.text }

    func makeView() -> UIView { textView }

    func load(_ document: FileDocument) {
        let editable = !document.isReadOnly && document.kind == .text
        guard loadedETag != document.etag else {
            // Connectivity can turn an already-loaded document into a read-only
            // cached view without changing its ETag. Reapply policy even when no
            // text/state replacement is necessary.
            setEditable(editable)
            return
        }
        applyingState = true
        loadedETag = document.etag
        let state: TextViewState
        if let language = Self.language(for: document) {
            state = TextViewState(text: document.content, theme: DefaultTheme(), language: language)
        } else {
            state = TextViewState(text: document.content, theme: DefaultTheme())
        }
        textView.setState(state)
        setEditable(editable)
        applyingState = false
    }

    func setEditable(_ editable: Bool) {
        textView.isEditable = editable
        textView.isSelectable = true
    }

    private static func language(for document: FileDocument) -> TreeSitterLanguage? {
        let hint = document.languageHint?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let pathExtension = (document.path as NSString).pathExtension.lowercased()
        let identifier = (hint?.isEmpty == false ? hint : nil) ?? pathExtension

        return switch identifier {
        case "bash", "shell", "shellscript", "sh", "zsh": .bash
        case "css": .css
        case "go", "golang": .go
        case "html", "htm": .html
        case "javascript", "javascriptreact", "js", "jsx", "mjs", "cjs":
            identifier == "jsx" || identifier == "javascriptreact" ? .jsx : .javaScript
        case "json", "jsonc": .json
        case "markdown", "md", "mdown": .markdown
        case "python", "py": .python
        case "swift": .swift
        case "toml": .toml
        case "tsx", "typescriptreact": .tsx
        case "typescript", "ts": .typeScript
        case "yaml", "yml": .yaml
        default: nil
        }
    }
}

// Runestone 0.5.2 predates Swift 6 actor annotations. TextView invokes its editor
// delegate from UIKit's main-thread editing pipeline.
extension RunestoneAdapter: @preconcurrency TextViewDelegate {
    func textViewDidChange(_ textView: TextView) {
        guard !applyingState else { return }
        onTextChange?(textView.text)
    }

    func textView(_ textView: TextView, canReplaceTextIn highlightedRange: HighlightedRange) -> Bool {
        textView.isEditable
    }
}

struct RunestoneSurface: UIViewRepresentable {
    let adapter: RunestoneAdapter

    func makeUIView(context: Context) -> UIView {
        adapter.makeView()
    }

    func updateUIView(_ uiView: UIView, context: Context) {}
}
