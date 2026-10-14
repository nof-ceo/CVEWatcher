import Foundation

/// EPSS — Exploit Prediction Scoring System (FIRST.org).
/// https://www.first.org/epss/api
struct EPSSService {

    struct Response: Decodable {
        let data: [Entry]
    }
    struct Entry: Decodable {
        let cve: String
        let epss: String
        let percentile: String
    }

    /// Возвращает словарь cveID -> epssScore (0...1) для списка CVE (максимум ~100 за запрос).
    static func fetchScores(for cveIDs: [String]) async throws -> [String: Double] {
        guard !cveIDs.isEmpty else { return [:] }
        let chunks = cveIDs.chunked(into: 100)
        var result: [String: Double] = [:]

        for chunk in chunks {
            var components = URLComponents(string: "https://api.first.org/data/v1/epss")!
            components.queryItems = [URLQueryItem(name: "cve", value: chunk.joined(separator: ","))]
            guard let url = components.url else { continue }

            let response = try await NetworkClient.fetchJSON(url: url, as: Response.self)
            for entry in response.data {
                result[entry.cve] = Double(entry.epss)
            }
        }
        return result
    }
}

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        guard size > 0 else { return [self] }
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0..<Swift.min($0 + size, count)])
        }
    }
}
