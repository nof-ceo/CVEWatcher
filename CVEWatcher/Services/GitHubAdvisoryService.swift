import Foundation

/// GitHub Security Advisories (GHSA).
struct GitHubAdvisoryService {

    struct Advisory: Decodable {
        let ghsa_id: String
        let cve_id: String?
        let summary: String?
        let description: String?
        let severity: String?
        let published_at: String?
        let updated_at: String?
        let html_url: String?
        let cvss: CVSS?
        let cwes: [CWE]?
        let vulnerabilities: [VulnerablePackage]?
    }
    struct CVSS: Decodable {
        let score: Double?
        let vector_string: String?
    }
    struct CWE: Decodable {
        let cwe_id: String?
    }
    struct VulnerablePackage: Decodable {
        let package: Package?
    }
    struct Package: Decodable {
        let name: String?
        let ecosystem: String?
    }

    static func fetchRecent(sinceISO: String, token: String?) async throws -> [CVEItem] {
        var components = URLComponents(string: "https://api.github.com/advisories")!
        components.queryItems = [
            URLQueryItem(name: "published", value: ">=\(sinceISO)"),
            URLQueryItem(name: "per_page", value: "100"),
            URLQueryItem(name: "sort", value: "published"),
            URLQueryItem(name: "direction", value: "desc")
        ]
        guard let url = components.url else { return [] }

        let advisories = try await GitHubAPI.get(url, token: token, as: [Advisory].self)

        return advisories.compactMap { advisory -> CVEItem? in
            guard let cveID = advisory.cve_id else { return nil }
            let pkg = advisory.vulnerabilities?.first?.package
            let cwes = (advisory.cwes ?? []).compactMap { $0.cwe_id }

            return CVEItem(
                cveID: cveID,
                title: advisory.summary ?? cveID,
                summary: advisory.description ?? advisory.summary ?? "",
                cvssScore: advisory.cvss?.score,
                cvssVector: advisory.cvss?.vector_string,
                vendor: pkg?.ecosystem,
                product: pkg?.name,
                publishedDate: GitHubAPI.parseDate(advisory.published_at),
                lastModifiedDate: GitHubAPI.parseDate(advisory.updated_at),
                tags: ["github-advisory"] + (pkg?.ecosystem.map { [$0.lowercased()] } ?? []),
                cwes: cwes,
                sourceURLs: [advisory.html_url].compactMap { $0 }
            )
        }
    }
}
