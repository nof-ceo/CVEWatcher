import Foundation

/// NVD API 2.0: https://nvd.nist.gov/developers/vulnerabilities
struct NVDService {

    struct Response: Decodable {
        let vulnerabilities: [VulnWrapper]
    }
    struct VulnWrapper: Decodable {
        let cve: CVE
    }
    struct CVE: Decodable {
        let id: String
        let vulnStatus: String?
        let published: String?
        let lastModified: String?
        let descriptions: [Description]?
        let metrics: Metrics?
        let weaknesses: [Weakness]?
        let configurations: [Configuration]?
        let references: [Reference]?
    }
    struct Description: Decodable {
        let lang: String
        let value: String
    }
    struct Weakness: Decodable {
        let description: [Description]?
    }
    struct Configuration: Decodable {
        let nodes: [Node]?
    }
    struct Node: Decodable {
        let cpeMatch: [CPEMatch]?
    }
    struct CPEMatch: Decodable {
        let vulnerable: Bool?
        let criteria: String?
    }
    struct Metrics: Decodable {
        let cvssMetricV31: [CVSSMetric]?
        let cvssMetricV30: [CVSSMetric]?
        let cvssMetricV2: [CVSSMetric]?
    }
    struct CVSSMetric: Decodable {
        let cvssData: CVSSData
    }
    struct CVSSData: Decodable {
        let baseScore: Double
        let vectorString: String?
    }
    struct Reference: Decodable {
        let url: String
    }

    private static func makeFormatter(withFraction: Bool) -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = withFraction ? "yyyy-MM-dd'T'HH:mm:ss.SSS" : "yyyy-MM-dd'T'HH:mm:ss"
        return formatter
    }

    /// CVE, опубликованные за последние `hours` часов.
    static func fetchRecent(hours: Int, apiKey: String?) async throws -> [CVEItem] {
        let formatter = makeFormatter(withFraction: true)
        let now = Date()
        let start = now.addingTimeInterval(-Double(hours) * 3600)
        return try await fetch([
            URLQueryItem(name: "pubStartDate", value: formatter.string(from: start)),
            URLQueryItem(name: "pubEndDate", value: formatter.string(from: now)),
            URLQueryItem(name: "resultsPerPage", value: "200")
        ], apiKey: apiKey)
    }

    /// CVE, изменённые за последние `hours` часов (так ловим смену CVSS и дополнение CPE/CWE).
    static func fetchModified(hours: Int, apiKey: String?) async throws -> [CVEItem] {
        let formatter = makeFormatter(withFraction: true)
        let now = Date()
        let start = now.addingTimeInterval(-Double(hours) * 3600)
        return try await fetch([
            URLQueryItem(name: "lastModStartDate", value: formatter.string(from: start)),
            URLQueryItem(name: "lastModEndDate", value: formatter.string(from: now)),
            URLQueryItem(name: "resultsPerPage", value: "500")
        ], apiKey: apiKey)
    }

    static func fetchByID(_ cveID: String, apiKey: String?) async throws -> CVEItem? {
        let items = try await fetch([URLQueryItem(name: "cveId", value: cveID)], apiKey: apiKey)
        return items.first
    }

    private static func fetch(_ queryItems: [URLQueryItem], apiKey: String?) async throws -> [CVEItem] {
        var components = URLComponents(string: "https://services.nvd.nist.gov/rest/json/cves/2.0")!
        components.queryItems = queryItems
        guard let url = components.url else { return [] }

        var headers: [String: String] = [:]
        if let apiKey, !apiKey.isEmpty { headers["apiKey"] = apiKey }

        let response = try await NetworkClient.fetchJSON(url: url, headers: headers, as: Response.self)
        return response.vulnerabilities.compactMap { convert($0.cve) }
    }

    private static func convert(_ cve: CVE) -> CVEItem? {
        if cve.vulnStatus == "Rejected" { return nil }
        let description = cve.descriptions?.first(where: { $0.lang == "en" })?.value ?? ""
        if description.hasPrefix("** REJECT **") { return nil }

        let metric = cve.metrics?.cvssMetricV31?.first
            ?? cve.metrics?.cvssMetricV30?.first
            ?? cve.metrics?.cvssMetricV2?.first

        let withFraction = makeFormatter(withFraction: true)
        let withoutFraction = makeFormatter(withFraction: false)
        func parseDate(_ string: String?) -> Date? {
            guard let string else { return nil }
            return withFraction.date(from: string) ?? withoutFraction.date(from: string)
        }

        // CWE
        var cwes: [String] = []
        for weakness in cve.weaknesses ?? [] {
            for d in weakness.description ?? [] where d.value.hasPrefix("CWE-") && !cwes.contains(d.value) {
                cwes.append(d.value)
            }
        }

        // CPE: vendor:product
        var pairs: [String] = []
        for config in cve.configurations ?? [] {
            for node in config.nodes ?? [] {
                for match in node.cpeMatch ?? [] where match.vulnerable ?? true {
                    guard let criteria = match.criteria else { continue }
                    let parts = criteria.split(separator: ":", omittingEmptySubsequences: false).map { String($0) }
                    guard parts.count > 4, parts[3] != "*", parts[4] != "*" else { continue }
                    let pair = "\(parts[3].lowercased()):\(parts[4].lowercased())"
                    if !pairs.contains(pair), pairs.count < 12 { pairs.append(pair) }
                }
            }
        }
        let firstParts = pairs.first?.split(separator: ":", maxSplits: 1).map { String($0) }

        let links = ["https://nvd.nist.gov/vuln/detail/\(cve.id)"] + (cve.references?.prefix(10).map { $0.url } ?? [])

        return CVEItem(
            cveID: cve.id,
            title: cve.id,
            summary: description,
            cvssScore: metric?.cvssData.baseScore,
            cvssVector: metric?.cvssData.vectorString,
            vendor: firstParts?.first,
            product: (firstParts?.count ?? 0) > 1 ? firstParts?[1] : nil,
            publishedDate: parseDate(cve.published),
            lastModifiedDate: parseDate(cve.lastModified),
            cwes: cwes,
            cpePairs: pairs,
            sourceURLs: links
        )
    }
}
