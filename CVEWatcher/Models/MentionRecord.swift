import Foundation
import SwiftData

/// Одно упоминание/источник CVE (статья, пост, репозиторий, advisory...).
/// Из них считаются дедупликация, достоверность и trending.
@Model
final class MentionRecord {
    var url: String
    var title: String
    var kindRaw: String
    var occurredAt: Date
    var detectedAt: Date
    /// true — "живой сигнал" (новости, соцсети, GitHub-репозитории); учитывается в trending.
    var isSignal: Bool

    var cve: CVEItem?

    init(url: String, title: String, kind: SourceKind, occurredAt: Date, isSignal: Bool, detectedAt: Date = .now) {
        self.url = url
        self.title = title
        self.kindRaw = kind.rawValue
        self.occurredAt = occurredAt
        self.detectedAt = detectedAt
        self.isSignal = isSignal
    }

    var kind: SourceKind {
        get { SourceKind(rawValue: kindRaw) ?? .other }
        set { kindRaw = newValue.rawValue }
    }
}
