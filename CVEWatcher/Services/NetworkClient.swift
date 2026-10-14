import Foundation

enum NetworkError: Error {
    case badStatus(Int)
    case decoding(Error)
    case rateLimited(Date)
}

/// Общий HTTP-клиент для JSON API. Текстовые/CSV/XML ответы обрабатываются через `fetchRawString`.
struct NetworkClient {

    static func fetchJSON<T: Decodable>(
        url: URL,
        headers: [String: String] = [:],
        as type: T.Type
    ) async throws -> T {
        var request = URLRequest(url: url)
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        request.setValue("CVEWatcher/1.0 (macOS)", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetworkError.badStatus(http.statusCode)
        }
        do {
            let decoder = JSONDecoder()
            return try decoder.decode(T.self, from: data)
        } catch {
            throw NetworkError.decoding(error)
        }
    }

    static func fetchRawString(url: URL, headers: [String: String] = [:]) async throws -> String {
        var request = URLRequest(url: url)
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        request.setValue("CVEWatcher/1.0 (macOS)", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetworkError.badStatus(http.statusCode)
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func fetchRawData(url: URL, headers: [String: String] = [:]) async throws -> Data {
        var request = URLRequest(url: url)
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        request.setValue("CVEWatcher/1.0 (macOS)", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetworkError.badStatus(http.statusCode)
        }
        return data
    }
}

/// Находит все идентификаторы CVE в произвольном тексте.
enum CVERegex {
    static func findAll(in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: "CVE-\\d{4}-\\d{4,7}", options: .caseInsensitive) else {
            return []
        }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        let matches = regex.matches(in: text, options: [], range: range)
        let ids = matches.compactMap { match -> String? in
            guard let r = Range(match.range, in: text) else { return nil }
            return String(text[r]).uppercased()
        }
        return Array(Set(ids))
    }
}

extension NetworkError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .badStatus(let code):
            return "HTTP \(code)"
        case .decoding(let error):
            return "ошибка разбора ответа (\(error.localizedDescription))"
        case .rateLimited(let date):
            let formatter = DateFormatter()
            formatter.timeStyle = .short
            return "лимит запросов GitHub, повтор после \(formatter.string(from: date)) (добавьте токен в Настройках)"
        }
    }
}
