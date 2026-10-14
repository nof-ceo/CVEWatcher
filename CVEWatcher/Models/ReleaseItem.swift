import Foundation
import SwiftData

/// Новый релиз в отслеживаемом GitHub-репозитории.
@Model
final class ReleaseItem {
    @Attribute(.unique) var url: String
    var repo: String
    var tag: String
    var name: String
    var publishedAt: Date?
    var bodyExcerpt: String
    var mentionsSecurity: Bool
    var cveIDsRaw: String
    var discoveredAt: Date

    init(url: String, repo: String, tag: String, name: String, publishedAt: Date?, bodyExcerpt: String, mentionsSecurity: Bool, cveIDs: [String]) {
        self.url = url
        self.repo = repo
        self.tag = tag
        self.name = name
        self.publishedAt = publishedAt
        self.bodyExcerpt = bodyExcerpt
        self.mentionsSecurity = mentionsSecurity
        self.cveIDsRaw = cveIDs.joined(separator: ",")
        self.discoveredAt = .now
    }

    var cveIDs: [String] { cveIDsRaw.isEmpty ? [] : cveIDsRaw.components(separatedBy: ",") }
}
