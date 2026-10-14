import Foundation

/// Упоминание CVE в статье/посте.
struct RSSMention: Sendable {
    let cveIDs: [String]
    let articleTitle: String
    let articleURL: String
    let articleSummary: String
    let publishedDate: Date?
    let kind: SourceKind
}

struct RSSFeedService {

    static let defaultFeeds: [String] = [
        // Новости и исследования
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "https://portswigger.net/research/rss",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://feeds.feedburner.com/Threatpost",
        // Reddit
        "https://www.reddit.com/r/netsec/new/.rss",
        "https://www.reddit.com/r/cybersecurity/new/.rss",
        "https://www.reddit.com/r/blueteamsec/new/.rss",
        // Вендорские бюллетени
        "https://api.msrc.microsoft.com/update-guide/rss",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "https://ubuntu.com/security/notices/rss.xml"
    ]

    static func fetchMentions(feedURLs: [String]) async -> [RSSMention] {
        var mentions: [RSSMention] = []
        await withTaskGroup(of: [RSSMention].self) { group in
            for feedURLString in feedURLs {
                group.addTask {
                    await fetchMentions(fromFeed: feedURLString)
                }
            }
            for await result in group {
                mentions.append(contentsOf: result)
            }
        }
        return mentions
    }

    private static func fetchMentions(fromFeed feedURLString: String) async -> [RSSMention] {
        guard let url = URL(string: feedURLString) else { return [] }

        var feedKind = SourceKind.classify(urlString: feedURLString)
        if feedKind == .other || feedKind == .forum { feedKind = .news }

        do {
            let data = try await NetworkClient.fetchRawData(url: url)
            let articles = RSSParser.parse(data: data)

            return articles.compactMap { article in
                let cveIDs = CVERegex.findAll(in: article.title + " " + article.summary)
                guard !cveIDs.isEmpty else { return nil }

                var kind = SourceKind.classify(urlString: article.link)
                if kind == .other || kind == .forum { kind = feedKind }

                return RSSMention(
                    cveIDs: cveIDs,
                    articleTitle: article.title,
                    articleURL: article.link,
                    articleSummary: article.summary,
                    publishedDate: article.publishedDate,
                    kind: kind
                )
            }
        } catch {
            print("RSS ошибка для \(feedURLString): \(error)")
            return []
        }
    }
}
