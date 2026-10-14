import Foundation

/// Поиск PoC/эксплойтов для конкретного CVE. Код не скачивается и не запускается.
struct PoCAggregatorService {

    // MARK: - GitHub

    static func searchGitHub(cveID: String, token: String?) async -> [PoCItem] {
        var components = URLComponents(string: "https://api.github.com/search/repositories")!
        components.queryItems = [
            URLQueryItem(name: "q", value: "\(cveID) in:name,description"),
            URLQueryItem(name: "sort", value: "stars"),
            URLQueryItem(name: "order", value: "desc"),
            URLQueryItem(name: "per_page", value: "10")
        ]
        guard let url = components.url else { return [] }

        do {
            let response = try await GitHubAPI.get(url, token: token, as: GitHubSearchResponse.self)
            var result: [PoCItem] = []

            for (index, repo) in response.items.enumerated() {
                var analysis = PoCAnalyzer.analyze(
                    cveID: cveID,
                    name: repo.full_name,
                    description: repo.description,
                    topics: repo.topics ?? [],
                    stars: repo.stargazers_count ?? 0,
                    isFork: repo.fork ?? false,
                    sizeKB: repo.size,
                    owner: repo.owner?.login,
                    files: nil
                )

                // Глубокий анализ списка файлов — только для лучших кандидатов и только с токеном.
                if index < 2, analysis.confidence >= 30, let token, !token.isEmpty,
                   let contentsURL = URL(string: "https://api.github.com/repos/\(repo.full_name)/contents") {
                    if let contents = try? await GitHubAPI.get(contentsURL, token: token, as: [GitHubContent].self) {
                        analysis = PoCAnalyzer.analyze(
                            cveID: cveID,
                            name: repo.full_name,
                            description: repo.description,
                            topics: repo.topics ?? [],
                            stars: repo.stargazers_count ?? 0,
                            isFork: repo.fork ?? false,
                            sizeKB: repo.size,
                            owner: repo.owner?.login,
                            files: contents.map { $0.name }
                        )
                    }
                }

                guard analysis.confidence >= 15 else { continue }
                result.append(PoCItem(
                    url: repo.html_url,
                    title: repo.full_name,
                    sourceType: .github,
                    starCount: repo.stargazers_count,
                    author: repo.owner?.login,
                    publishedDate: GitHubAPI.parseDate(repo.created_at),
                    confidence: analysis.confidence,
                    isExploit: analysis.isExploit,
                    topics: repo.topics ?? [],
                    analysisNote: analysis.reasons.joined(separator: ", ")
                ))
            }
            return result
        } catch {
            print("GitHub PoC поиск для \(cveID) не удался: \(error)")
            return []
        }
    }

    // MARK: - Nuclei (GitHub Code Search, нужен токен)

    struct CodeSearchResponse: Decodable {
        let items: [CodeItem]
    }
    struct CodeItem: Decodable {
        let name: String
        let html_url: String
    }

    static func searchNucleiTemplates(cveID: String, token: String?) async -> [PoCItem] {
        guard let token, !token.isEmpty else { return [] }

        var components = URLComponents(string: "https://api.github.com/search/code")!
        components.queryItems = [
            URLQueryItem(name: "q", value: "\(cveID) repo:projectdiscovery/nuclei-templates"),
            URLQueryItem(name: "per_page", value: "5")
        ]
        guard let url = components.url else { return [] }

        do {
            let response = try await GitHubAPI.get(url, token: token, as: CodeSearchResponse.self)
            return response.items.map { item in
                PoCItem(
                    url: item.html_url,
                    title: "Nuclei template: \(item.name)",
                    sourceType: .nucleiTemplate,
                    confidence: 90,
                    analysisNote: "шаблон ProjectDiscovery"
                )
            }
        } catch {
            print("Nuclei поиск для \(cveID) не удался: \(error)")
            return []
        }
    }

    // MARK: - Exploit-DB (CSV-индекс)

    fileprivate struct ExploitDBEntry {
        let id: String
        let title: String
        let date: Date?
    }

    fileprivate actor ExploitDBIndex {
        static let shared = ExploitDBIndex()

        private var index: [String: [ExploitDBEntry]]?
        private var nextRetry: Date?

        func lookup(_ cveID: String) async -> [ExploitDBEntry] {
            if index == nil {
                if let nextRetry, nextRetry > Date() { return [] }
                index = await ExploitDBIndex.load()
                if index == nil { nextRetry = Date().addingTimeInterval(30 * 60) }
            }
            return index?[cveID.uppercased()] ?? []
        }

        private static func load() async -> [String: [ExploitDBEntry]]? {
            guard let url = URL(string: "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv") else { return nil }
            do {
                let csv = try await NetworkClient.fetchRawString(url: url)
                let dateFormatter = DateFormatter()
                dateFormatter.locale = Locale(identifier: "en_US_POSIX")
                dateFormatter.dateFormat = "yyyy-MM-dd"

                var result: [String: [ExploitDBEntry]] = [:]
                var isHeader = true
                for line in csv.split(whereSeparator: \.isNewline) {
                    if isHeader { isHeader = false; continue }
                    let fields = parseCSVLine(String(line))
                    // id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,...
                    guard fields.count > 11 else { continue }
                    let entry = ExploitDBEntry(id: fields[0], title: fields[2], date: dateFormatter.date(from: fields[3]))
                    let codes = fields[11].split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces).uppercased() }
                    for code in codes where code.hasPrefix("CVE-") {
                        result[code, default: []].append(entry)
                    }
                }
                return result
            } catch {
                print("Не удалось загрузить индекс Exploit-DB: \(error)")
                return nil
            }
        }

        private static func parseCSVLine(_ line: String) -> [String] {
            var fields: [String] = []
            var current = ""
            var inQuotes = false
            for char in line {
                if char == "\"" {
                    inQuotes.toggle()
                } else if char == "," && !inQuotes {
                    fields.append(current)
                    current = ""
                } else {
                    current.append(char)
                }
            }
            fields.append(current)
            return fields
        }
    }

    static func searchExploitDB(cveID: String) async -> [PoCItem] {
        let matches = await ExploitDBIndex.shared.lookup(cveID)
        return matches.map { entry in
            PoCItem(
                url: "https://www.exploit-db.com/exploits/\(entry.id)",
                title: entry.title.isEmpty ? "Exploit-DB #\(entry.id)" : entry.title,
                sourceType: .exploitDB,
                publishedDate: entry.date,
                confidence: 95,
                isExploit: true,
                analysisNote: "запись Exploit-DB"
            )
        }
    }

    // MARK: - Metasploit

    static func searchMetasploit(cveID: String) async -> [PoCItem] {
        let modules = await MetasploitIndex.shared.lookup(cveID)
        return modules.map { module in
            PoCItem(
                url: module.url,
                title: "Metasploit: \(module.fullname)",
                sourceType: .metasploit,
                publishedDate: module.modTime,
                confidence: 98,
                isExploit: true,
                analysisNote: "модуль Metasploit (дата — приблизительно, по mod_time)"
            )
        }
    }

    // MARK: - Комбинированный поиск

    static func findAllPoCs(
        cveID: String,
        githubToken: String?,
        useGitHub: Bool,
        useNuclei: Bool,
        useExploitDB: Bool,
        useMetasploit: Bool
    ) async -> [PoCItem] {
        var result: [PoCItem] = []
        if useGitHub { result += await searchGitHub(cveID: cveID, token: githubToken) }
        if useNuclei { result += await searchNucleiTemplates(cveID: cveID, token: githubToken) }
        if useExploitDB { result += await searchExploitDB(cveID: cveID) }
        if useMetasploit { result += await searchMetasploit(cveID: cveID) }
        return result
    }
}
