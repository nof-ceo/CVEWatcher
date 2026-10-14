import Foundation

struct MetasploitModule: Codable, Sendable {
    let fullname: String
    let path: String
    let modTime: Date?
    var url: String { "https://github.com/rapid7/metasploit-framework/blob/master\(path)" }
}

/// Индекс модулей Metasploit (CVE → модули). Строится из публичного файла метаданных,
/// кэшируется на диск на 24 часа.
actor MetasploitIndex {
    static let shared = MetasploitIndex()

    private var index: [String: [MetasploitModule]]?
    private var nextRetry: Date?

    private struct CacheFile: Codable {
        let savedAt: Date
        let index: [String: [MetasploitModule]]
    }

    func lookup(_ cveID: String) async -> [MetasploitModule] {
        if index == nil {
            if let cached = Self.loadCache() {
                index = cached
            } else {
                if let nextRetry, nextRetry > Date() { return [] }
                index = await Self.download()
                if index == nil { nextRetry = Date().addingTimeInterval(30 * 60) }
            }
        }
        return index?[cveID.uppercased()] ?? []
    }

    private static var cacheURL: URL? {
        guard let dir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else { return nil }
        let folder = dir.appendingPathComponent("CVEWatcher", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder.appendingPathComponent("msf_index.json")
    }

    private static func loadCache() -> [String: [MetasploitModule]]? {
        guard let url = cacheURL, let data = try? Data(contentsOf: url),
              let file = try? JSONDecoder().decode(CacheFile.self, from: data),
              Date().timeIntervalSince(file.savedAt) < 24 * 3600 else { return nil }
        return file.index
    }

    private static func saveCache(_ index: [String: [MetasploitModule]]) {
        guard let url = cacheURL else { return }
        let file = CacheFile(savedAt: Date(), index: index)
        if let data = try? JSONEncoder().encode(file) {
            try? data.write(to: url)
        }
    }

    private static func download() async -> [String: [MetasploitModule]]? {
        guard let url = URL(string: "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json") else { return nil }
        do {
            let data = try await NetworkClient.fetchRawData(url: url)
            guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }

            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"

            var result: [String: [MetasploitModule]] = [:]
            for (_, value) in root {
                guard let module = value as? [String: Any],
                      (module["type"] as? String) == "exploit",
                      let fullname = module["fullname"] as? String,
                      let path = module["path"] as? String,
                      let references = module["references"] as? [String] else { continue }

                let modTime = (module["mod_time"] as? String).flatMap { formatter.date(from: $0) }
                let entry = MetasploitModule(fullname: fullname, path: path, modTime: modTime)
                for ref in references where ref.uppercased().hasPrefix("CVE-") {
                    result[ref.uppercased(), default: []].append(entry)
                }
            }
            saveCache(result)
            return result
        } catch {
            print("Не удалось загрузить индекс Metasploit: \(error)")
            return nil
        }
    }
}
