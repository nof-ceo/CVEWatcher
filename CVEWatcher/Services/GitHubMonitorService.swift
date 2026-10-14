import Foundation

struct DiscoveredRepo: Sendable {
    let fullName: String
    let url: String
    let description: String?
    let stars: Int
    let createdAt: Date?
    let owner: String?
    let topics: [String]
    let cveIDs: [String]
    let confidence: Int
    let isExploit: Bool
    let reasons: [String]
}

struct ReleaseInfo: Sendable {
    let repo: String
    let tag: String
    let name: String
    let url: String
    let publishedAt: Date?
    let body: String
    let mentionsSecurity: Bool
    let cveIDs: [String]
}

/// Мониторинг GitHub: новые репозитории с CVE/PoC/exploit и релизы отслеживаемых репозиториев.
enum GitHubMonitorService {

    // MARK: - Discovery

    static func discover(token: String?) async -> (repos: [DiscoveredRepo], error: String?) {
        let calendar = Calendar(identifier: .gregorian)
        let now = Date()
        let year = calendar.component(.year, from: now)

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd"
        let since = formatter.string(from: now.addingTimeInterval(-2 * 86400))

        var years = [year]
        if calendar.component(.month, from: now) <= 2 { years.append(year - 1) }

        var queries: [String] = []
        for y in years {
            queries.append("CVE-\(y) in:name created:>=\(since)")
            queries.append("CVE-\(y) poc in:name,description created:>=\(since)")
            queries.append("CVE-\(y) exploit in:name,description created:>=\(since)")
        }

        var byName: [String: GitHubRepo] = [:]
        var errorText: String?

        for query in queries {
            var components = URLComponents(string: "https://api.github.com/search/repositories")!
            components.queryItems = [
                URLQueryItem(name: "q", value: query),
                URLQueryItem(name: "sort", value: "updated"),
                URLQueryItem(name: "order", value: "desc"),
                URLQueryItem(name: "per_page", value: "50")
            ]
            guard let url = components.url else { continue }
            do {
                let response = try await GitHubAPI.get(url, token: token, as: GitHubSearchResponse.self)
                for repo in response.items { byName[repo.full_name] = repo }
            } catch {
                errorText = "GitHub Discovery: \(error.localizedDescription)"
                break
            }
        }

        let currentYear = year
        var result: [DiscoveredRepo] = []
        for repo in byName.values {
            let ids = CVERegex.findAll(in: repo.full_name + " " + (repo.description ?? ""))
                .filter { isPlausible($0, currentYear: currentYear) }
            guard !ids.isEmpty else { continue }

            let analysis = PoCAnalyzer.analyze(
                cveID: nil,
                name: repo.full_name,
                description: repo.description,
                topics: repo.topics ?? [],
                stars: repo.stargazers_count ?? 0,
                isFork: repo.fork ?? false,
                sizeKB: repo.size,
                owner: repo.owner?.login,
                files: nil
            )
            guard analysis.confidence >= 25 else { continue }

            result.append(DiscoveredRepo(
                fullName: repo.full_name,
                url: repo.html_url,
                description: repo.description,
                stars: repo.stargazers_count ?? 0,
                createdAt: GitHubAPI.parseDate(repo.created_at),
                owner: repo.owner?.login,
                topics: repo.topics ?? [],
                cveIDs: ids.sorted(),
                confidence: analysis.confidence,
                isExploit: analysis.isExploit,
                reasons: analysis.reasons
            ))
        }
        return (result, errorText)
    }

    private static func isPlausible(_ cveID: String, currentYear: Int) -> Bool {
        let parts = cveID.split(separator: "-")
        guard parts.count == 3, let year = Int(parts[1]) else { return false }
        return year >= 1999 && year <= currentYear
    }

    // MARK: - Releases

    struct GitHubRelease: Decodable {
        let tag_name: String
        let name: String?
        let html_url: String
        let published_at: String?
        let body: String?
        let draft: Bool?
    }

    static func fetchReleases(repos: [String], token: String?) async -> (releases: [ReleaseInfo], error: String?) {
        var result: [ReleaseInfo] = []
        var errorText: String?

        for repo in repos {
            let trimmed = repo.trimmingCharacters(in: .whitespaces)
            guard trimmed.split(separator: "/").count == 2, !trimmed.contains(" "),
                  let url = URL(string: "https://api.github.com/repos/\(trimmed)/releases?per_page=5") else { continue }
            do {
                let releases = try await GitHubAPI.get(url, token: token, as: [GitHubRelease].self)
                for release in releases where release.draft != true {
                    let body = release.body ?? ""
                    let securityRange = body.range(
                        of: "security|vulnerab|CVE-\\d{4}-\\d+|advisory",
                        options: [.regularExpression, .caseInsensitive]
                    )
                    result.append(ReleaseInfo(
                        repo: trimmed,
                        tag: release.tag_name,
                        name: release.name ?? release.tag_name,
                        url: release.html_url,
                        publishedAt: GitHubAPI.parseDate(release.published_at),
                        body: String(body.prefix(800)),
                        mentionsSecurity: securityRange != nil,
                        cveIDs: CVERegex.findAll(in: body)
                    ))
                }
            } catch {
                errorText = "GitHub Releases (\(trimmed)): \(error.localizedDescription)"
                if case NetworkError.rateLimited = error { break }
            }
        }
        return (result, errorText)
    }
}
