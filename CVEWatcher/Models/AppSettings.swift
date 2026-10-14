import Foundation
import Combine

/// Источники, которые можно включать/выключать в настройках.
enum DataSource: String, Codable, CaseIterable, Identifiable {
    case nvd = "NVD"
    case cisaKEV = "CISA KEV"
    case githubAdvisories = "GitHub Advisories"
    case epss = "EPSS"
    case rssNews = "RSS / Новости"
    case githubPoCSearch = "GitHub PoC Search"
    case exploitDB = "Exploit-DB"
    case nucleiTemplates = "Nuclei Templates"
    case xTwitter = "X (Twitter)"
    case githubDiscovery = "GitHub Discovery"
    case githubReleases = "GitHub Releases"
    case metasploit = "Metasploit"

    var id: String { rawValue }
}

/// Простые параметры живут в UserDefaults, секреты (токены) — в Keychain.
final class AppSettings: ObservableObject {

    // MARK: - Опрос

    @Published var pollingIntervalSeconds: Double {
        didSet { UserDefaults.standard.set(pollingIntervalSeconds, forKey: Keys.pollingInterval) }
    }

    // MARK: - Уведомления

    @Published var minCVSSForNotification: Double {
        didSet { UserDefaults.standard.set(minCVSSForNotification, forKey: Keys.minCVSS) }
    }
    @Published var notifyNewVuln: Bool {
        didSet { UserDefaults.standard.set(notifyNewVuln, forKey: Keys.notifyNewVuln) }
    }
    @Published var notifyPoC: Bool {
        didSet { UserDefaults.standard.set(notifyPoC, forKey: Keys.notifyPoC) }
    }
    @Published var notifyExploit: Bool {
        didSet { UserDefaults.standard.set(notifyExploit, forKey: Keys.notifyExploit) }
    }
    @Published var notifyKEV: Bool {
        didSet { UserDefaults.standard.set(notifyKEV, forKey: Keys.notifyKEV) }
    }
    @Published var notifyTrending: Bool {
        didSet { UserDefaults.standard.set(notifyTrending, forKey: Keys.notifyTrending) }
    }
    /// Минимальная достоверность источников (0...1), ниже которой уведомления не показываются.
    @Published var minSourceConfidenceForNotification: Double {
        didSet { UserDefaults.standard.set(minSourceConfidenceForNotification, forKey: Keys.minConfidence) }
    }

    // MARK: - Источники

    @Published var enabledSources: Set<DataSource> {
        didSet { UserDefaults.standard.set(enabledSources.map { $0.rawValue }, forKey: Keys.enabledSources) }
    }

    @Published var watchedKeywords: [String] {
        didSet { UserDefaults.standard.set(watchedKeywords, forKey: Keys.watchedKeywords) }
    }

    @Published var customRSSFeeds: [String] {
        didSet { UserDefaults.standard.set(customRSSFeeds, forKey: Keys.customRSSFeeds) }
    }

    @Published var nitterBaseURL: String {
        didSet { UserDefaults.standard.set(nitterBaseURL, forKey: Keys.nitterBaseURL) }
    }

    @Published var xSearchQueries: [String] {
        didSet { UserDefaults.standard.set(xSearchQueries, forKey: Keys.xSearchQueries) }
    }

    /// Репозитории (owner/name), за релизами которых следим.
    @Published var watchedGitHubRepos: [String] {
        didSet { UserDefaults.standard.set(watchedGitHubRepos, forKey: Keys.watchedRepos) }
    }

    // MARK: - Watchlist

    @Published var watchlist: [WatchEntry] {
        didSet { Self.saveJSON(watchlist, key: Keys.watchlist) }
    }

    /// true — показывать в списках и уведомлять только то, что совпало с watchlist.
    @Published var watchlistOnly: Bool {
        didSet { UserDefaults.standard.set(watchlistOnly, forKey: Keys.watchlistOnly) }
    }

    // MARK: - Достоверность

    @Published var sourceWeights: [String: Double] {
        didSet { Self.saveJSON(sourceWeights, key: Keys.sourceWeights) }
    }

    @Published var minPoCConfidence: Int {
        didSet {
            UserDefaults.standard.set(minPoCConfidence, forKey: Keys.minPoCConfidence)
            Thresholds.minPoCConfidence = minPoCConfidence
        }
    }

    func weight(for kind: SourceKind) -> Double {
        sourceWeights[kind.rawValue] ?? kind.defaultWeight
    }

    // MARK: - Секреты (Keychain)

    var nvdAPIKey: String {
        get { KeychainHelper.shared.read(key: Keys.nvdAPIKey) ?? "" }
        set { KeychainHelper.shared.save(key: Keys.nvdAPIKey, value: newValue) }
    }

    var githubToken: String {
        get { KeychainHelper.shared.read(key: Keys.githubToken) ?? "" }
        set { KeychainHelper.shared.save(key: Keys.githubToken, value: newValue) }
    }

    var xBearerToken: String {
        get { KeychainHelper.shared.read(key: Keys.xBearerToken) ?? "" }
        set { KeychainHelper.shared.save(key: Keys.xBearerToken, value: newValue) }
    }

    // MARK: - Init

    init() {
        let defaults = UserDefaults.standard

        self.pollingIntervalSeconds = defaults.object(forKey: Keys.pollingInterval) as? Double ?? 120
        self.minCVSSForNotification = defaults.object(forKey: Keys.minCVSS) as? Double ?? 7.0
        self.notifyNewVuln = defaults.object(forKey: Keys.notifyNewVuln) as? Bool ?? true
        self.notifyPoC = defaults.object(forKey: Keys.notifyPoC) as? Bool ?? true
        self.notifyExploit = defaults.object(forKey: Keys.notifyExploit) as? Bool ?? true
        self.notifyKEV = defaults.object(forKey: Keys.notifyKEV) as? Bool ?? true
        self.notifyTrending = defaults.object(forKey: Keys.notifyTrending) as? Bool ?? false
        self.minSourceConfidenceForNotification = defaults.object(forKey: Keys.minConfidence) as? Double ?? 0

        // Источники: при обновлении включаем новые по умолчанию.
        var sources: Set<DataSource>
        if let raw = defaults.array(forKey: Keys.enabledSources) as? [String] {
            sources = Set(raw.compactMap { DataSource(rawValue: $0) })
            if defaults.integer(forKey: Keys.sourcesVersion) < 2 {
                sources.formUnion([.githubDiscovery, .githubReleases, .metasploit])
            }
        } else {
            sources = Set(DataSource.allCases)
        }
        defaults.set(2, forKey: Keys.sourcesVersion)
        self.enabledSources = sources

        self.watchedKeywords = defaults.array(forKey: Keys.watchedKeywords) as? [String] ?? []

        // RSS: при обновлении добавляем новые ленты по умолчанию (Reddit, вендоры).
        var feeds = defaults.array(forKey: Keys.customRSSFeeds) as? [String] ?? RSSFeedService.defaultFeeds
        if defaults.integer(forKey: Keys.feedsVersion) < 2 {
            for feed in RSSFeedService.defaultFeeds where !feeds.contains(feed) {
                feeds.append(feed)
            }
        }
        defaults.set(2, forKey: Keys.feedsVersion)
        self.customRSSFeeds = feeds

        self.nitterBaseURL = defaults.string(forKey: Keys.nitterBaseURL) ?? ""
        self.xSearchQueries = defaults.array(forKey: Keys.xSearchQueries) as? [String] ?? ["CVE-2026", "0day", "exploit poc"]
        self.watchedGitHubRepos = defaults.array(forKey: Keys.watchedRepos) as? [String] ?? [
            "kubernetes/kubernetes", "spring-projects/spring-framework", "apache/struts",
            "openssl/openssl", "projectdiscovery/nuclei-templates"
        ]

        // Watchlist: сохранённые + недостающие записи каталога.
        var list = Self.loadJSON([WatchEntry].self, key: Keys.watchlist) ?? []
        for entry in WatchCatalog.entries where !list.contains(where: { $0.id == entry.id }) {
            list.append(entry)
        }
        self.watchlist = list
        self.watchlistOnly = defaults.bool(forKey: Keys.watchlistOnly)

        self.sourceWeights = Self.loadJSON([String: Double].self, key: Keys.sourceWeights) ?? [:]
        let poc = defaults.object(forKey: Keys.minPoCConfidence) as? Int ?? 40
        self.minPoCConfidence = poc
        Thresholds.minPoCConfidence = poc
    }

    private static func saveJSON<T: Encodable>(_ value: T, key: String) {
        if let data = try? JSONEncoder().encode(value) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    private static func loadJSON<T: Decodable>(_ type: T.Type, key: String) -> T? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    private enum Keys {
        static let pollingInterval = "pollingIntervalSeconds"
        static let minCVSS = "minCVSSForNotification"
        static let notifyNewVuln = "notifyNewVuln"
        static let notifyPoC = "notifyPoC"
        static let notifyExploit = "notifyExploit"
        static let notifyKEV = "notifyKEV"
        static let notifyTrending = "notifyTrending"
        static let minConfidence = "minSourceConfidenceForNotification"
        static let enabledSources = "enabledSources"
        static let sourcesVersion = "sourcesVersion"
        static let feedsVersion = "feedsVersion"
        static let watchedKeywords = "watchedKeywords"
        static let customRSSFeeds = "customRSSFeeds"
        static let nitterBaseURL = "nitterBaseURL"
        static let xSearchQueries = "xSearchQueries"
        static let watchedRepos = "watchedGitHubRepos"
        static let watchlist = "watchlistEntries"
        static let watchlistOnly = "watchlistOnly"
        static let sourceWeights = "sourceWeights"
        static let minPoCConfidence = "minPoCConfidence"
        static let nvdAPIKey = "nvdAPIKey"
        static let githubToken = "githubToken"
        static let xBearerToken = "xBearerToken"
    }
}
