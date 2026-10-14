import Foundation
import SwiftData

@Model
final class CVEItem {
    @Attribute(.unique) var cveID: String
    var title: String
    var summary: String
    var cvssScore: Double?
    var cvssVector: String?
    var vendor: String?
    var product: String?
    var publishedDate: Date?
    var lastModifiedDate: Date?
    var isKEV: Bool
    var kevDueDate: Date?
    var epssScore: Double?
    var tagsRaw: String // CSV
    var isFavorite: Bool
    var sourceURLsRaw: String // служебное поле: ссылки, пришедшие от сервисов (превращаются в MentionRecord)
    var discoveredAt: Date
    var hasBeenNotified: Bool
    var pocCheckedAt: Date?

    // v2 (у всех есть значения по умолчанию — нужно для миграции существующей базы)
    var cwesRaw: String = ""
    var cpeRaw: String = ""              // "apache:tomcat|apache:http_server"
    var kevDateAdded: Date?
    var notifiedKindsRaw: String = ""
    var isWatched: Bool = false
    var watchLabelsRaw: String = ""
    var trendScore: Double = 0
    var trendMentions1h: Int = 0
    var sourceConfidence: Double = 0
    var fingerprint: String = ""
    var searchBlob: String = ""
    var nvdCheckedAt: Date?

    @Relationship(deleteRule: .cascade, inverse: \PoCItem.cve)
    var pocs: [PoCItem] = []

    @Relationship(deleteRule: .cascade, inverse: \MentionRecord.cve)
    var mentions: [MentionRecord] = []

    @Relationship(deleteRule: .cascade, inverse: \CVESnapshot.cve)
    var snapshots: [CVESnapshot] = []

    init(
        cveID: String,
        title: String = "",
        summary: String = "",
        cvssScore: Double? = nil,
        cvssVector: String? = nil,
        vendor: String? = nil,
        product: String? = nil,
        publishedDate: Date? = nil,
        lastModifiedDate: Date? = nil,
        isKEV: Bool = false,
        kevDueDate: Date? = nil,
        kevDateAdded: Date? = nil,
        epssScore: Double? = nil,
        tags: [String] = [],
        cwes: [String] = [],
        cpePairs: [String] = [],
        isFavorite: Bool = false,
        sourceURLs: [String] = [],
        discoveredAt: Date = .now,
        hasBeenNotified: Bool = false
    ) {
        self.cveID = cveID
        self.title = title
        self.summary = summary
        self.cvssScore = cvssScore
        self.cvssVector = cvssVector
        self.vendor = vendor
        self.product = product
        self.publishedDate = publishedDate
        self.lastModifiedDate = lastModifiedDate
        self.isKEV = isKEV
        self.kevDueDate = kevDueDate
        self.kevDateAdded = kevDateAdded
        self.epssScore = epssScore
        self.tagsRaw = tags.joined(separator: ",")
        self.cwesRaw = cwes.joined(separator: ",")
        self.cpeRaw = cpePairs.joined(separator: "|")
        self.isFavorite = isFavorite
        self.sourceURLsRaw = sourceURLs.joined(separator: "|")
        self.discoveredAt = discoveredAt
        self.hasBeenNotified = hasBeenNotified
    }

    var tags: [String] {
        get { tagsRaw.isEmpty ? [] : tagsRaw.components(separatedBy: ",") }
        set { tagsRaw = newValue.joined(separator: ",") }
    }

    var sourceURLs: [String] {
        get { sourceURLsRaw.isEmpty ? [] : sourceURLsRaw.components(separatedBy: "|") }
        set { sourceURLsRaw = newValue.joined(separator: "|") }
    }

    func addTagIfMissing(_ tag: String) {
        var current = tags
        if !current.contains(tag) {
            current.append(tag)
            tags = current
        }
    }

    func removeTag(_ tag: String) {
        let current = tags
        if current.contains(tag) {
            tags = current.filter { $0 != tag }
        }
    }

    var severityLabel: String {
        guard let score = cvssScore else { return "Неизвестно" }
        switch score {
        case 9...10: return "Критическая"
        case 7..<9: return "Высокая"
        case 4..<7: return "Средняя"
        case 0.1..<4: return "Низкая"
        default: return "Неизвестно"
        }
    }
}
