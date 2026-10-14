import Foundation
import SwiftData

enum PoCSourceType: String, Codable, CaseIterable {
    case github = "GitHub"
    case exploitDB = "Exploit-DB"
    case nucleiTemplate = "Nuclei Template"
    case metasploit = "Metasploit"
    case other = "Другое"

    var sourceKind: SourceKind {
        switch self {
        case .github: return .github
        case .exploitDB: return .exploitDB
        case .nucleiTemplate: return .nuclei
        case .metasploit: return .metasploit
        case .other: return .other
        }
    }
}

@Model
final class PoCItem {
    var url: String
    var title: String
    var sourceTypeRaw: String
    var starCount: Int?
    var author: String?
    var publishedDate: Date?
    var addedAt: Date

    // v2: автоматическая оценка
    var confidence: Int = 50
    var isExploit: Bool = false
    var topicsRaw: String = ""
    var analysisNote: String = ""

    var cve: CVEItem?

    init(
        url: String,
        title: String,
        sourceType: PoCSourceType,
        starCount: Int? = nil,
        author: String? = nil,
        publishedDate: Date? = nil,
        addedAt: Date = .now,
        confidence: Int = 50,
        isExploit: Bool = false,
        topics: [String] = [],
        analysisNote: String = ""
    ) {
        self.url = url
        self.title = title
        self.sourceTypeRaw = sourceType.rawValue
        self.starCount = starCount
        self.author = author
        self.publishedDate = publishedDate
        self.addedAt = addedAt
        self.confidence = confidence
        self.isExploit = isExploit
        self.topicsRaw = topics.joined(separator: ",")
        self.analysisNote = analysisNote
    }

    var sourceType: PoCSourceType {
        get { PoCSourceType(rawValue: sourceTypeRaw) ?? .other }
        set { sourceTypeRaw = newValue.rawValue }
    }

    /// Рабочий эксплойт (а не просто PoC/шаблон обнаружения).
    var isExploitGrade: Bool {
        sourceType == .exploitDB || sourceType == .metasploit || isExploit
    }

    /// Дата события для цепочки CVE → PoC → Exploit.
    var eventDate: Date { publishedDate ?? addedAt }

    /// true, если точной даты нет (Nuclei) или дата — приблизительная (Metasploit mod_time).
    var isDateApproximate: Bool {
        publishedDate == nil || sourceType == .metasploit
    }
}
