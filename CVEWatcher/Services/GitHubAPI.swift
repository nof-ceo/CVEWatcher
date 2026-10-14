import Foundation

struct GitHubOwner: Decodable {
    let login: String
}

struct GitHubRepo: Decodable {
    let full_name: String
    let html_url: String
    let description: String?
    let stargazers_count: Int?
    let created_at: String?
    let pushed_at: String?
    let owner: GitHubOwner?
    let topics: [String]?
    let language: String?
    let fork: Bool?
    let size: Int?
}

struct GitHubSearchResponse: Decodable {
    let items: [GitHubRepo]
}

struct GitHubContent: Decodable {
    let name: String
    let type: String
}

/// Общий лимитер: после 403/429 с исчерпанным лимитом GitHub не долбим до сброса.
actor GitHubRateLimiter {
    static let shared = GitHubRateLimiter()
    private var blockedUntil: Date?

    func blockedDate() -> Date? {
        if let blockedUntil, blockedUntil > Date() { return blockedUntil }
        return nil
    }

    func block(until date: Date) { blockedUntil = date }
    func reset() { blockedUntil = nil }
}

enum GitHubAPI {

    static func get<T: Decodable>(_ url: URL, token: String?, as type: T.Type) async throws -> T {
        if let until = await GitHubRateLimiter.shared.blockedDate() {
            throw NetworkError.rateLimited(until)
        }

        var request = URLRequest(url: url)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("CVEWatcher/1.0 (macOS)", forHTTPHeaderField: "User-Agent")
        if let token, !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await URLSession.shared.data(for: request)

        if let http = response as? HTTPURLResponse {
            if http.statusCode == 403 || http.statusCode == 429 {
                let remaining = http.value(forHTTPHeaderField: "x-ratelimit-remaining")
                let retryAfter = http.value(forHTTPHeaderField: "retry-after")
                if http.statusCode == 429 || remaining == "0" || retryAfter != nil {
                    var resetDate = Date().addingTimeInterval(120)
                    if let reset = http.value(forHTTPHeaderField: "x-ratelimit-reset"), let seconds = TimeInterval(reset) {
                        resetDate = Date(timeIntervalSince1970: seconds)
                    }
                    if let retryAfter, let seconds = TimeInterval(retryAfter) {
                        resetDate = Date().addingTimeInterval(seconds)
                    }
                    let capped = min(resetDate, Date().addingTimeInterval(15 * 60))
                    await GitHubRateLimiter.shared.block(until: capped)
                    throw NetworkError.rateLimited(capped)
                }
            }
            guard (200...299).contains(http.statusCode) else {
                throw NetworkError.badStatus(http.statusCode)
            }
        }

        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw NetworkError.decoding(error)
        }
    }

    static func parseDate(_ string: String?) -> Date? {
        guard let string else { return nil }
        let plain = ISO8601DateFormatter()
        if let date = plain.date(from: string) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: string)
    }
}
