import Foundation
import Combine
import SwiftData

/// Один цикл опроса: источники → слияние → производные данные → уведомления.
/// Каждый источник независим: ошибка одного не останавливает остальные.
@MainActor
final class AggregationCoordinator: ObservableObject {

    private let modelContext: ModelContext
    private let settings: AppSettings
    private let notificationManager: NotificationManager

    @Published var isRunning = false
    @Published var lastRunDate: Date?
    @Published var statusMessages: [String] = []

    private var lastDiscoveryRun: Date?
    private var lastReleasesRun: Date?
    private let baselineKey = "notificationBaselineV2"

    init(modelContext: ModelContext, settings: AppSettings, notificationManager: NotificationManager) {
        self.modelContext = modelContext
        self.settings = settings
        self.notificationManager = notificationManager
    }

    // MARK: - Цикл

    func runCycle() async {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }

        var errors: [String] = []
        let sources = settings.enabledSources
        let githubToken: String? = settings.githubToken.isEmpty ? nil : settings.githubToken

        // 1. NVD: новые + изменённые
        if sources.contains(.nvd) {
            let key: String? = settings.nvdAPIKey.isEmpty ? nil : settings.nvdAPIKey
            do {
                let items = try await NVDService.fetchRecent(hours: 12, apiKey: key)
                for item in items { upsert(item, authoritative: true, insertIfMissing: true) }
                let modified = try await NVDService.fetchModified(hours: 3, apiKey: key)
                for item in modified { upsert(item, authoritative: true, insertIfMissing: false) }
            } catch {
                errors.append("NVD: \(error.localizedDescription)")
            }
            saveContext()
        }

        // 2. GitHub Security Advisories
        if sources.contains(.githubAdvisories) {
            do {
                let since = ISO8601DateFormatter().string(from: Date().addingTimeInterval(-24 * 3600))
                let items = try await GitHubAdvisoryService.fetchRecent(sinceISO: since, token: githubToken)
                for item in items { upsert(item, authoritative: false, insertIfMissing: true) }
            } catch {
                errors.append("GitHub Advisories: \(error.localizedDescription)")
            }
            saveContext()
        }

        // 3. CISA KEV
        if sources.contains(.cisaKEV) {
            do {
                let entries = try await CISAKEVService.fetchRecentlyAdded(days: 7)
                applyKEV(entries: entries)
            } catch {
                errors.append("CISA KEV: \(error.localizedDescription)")
            }
            saveContext()
        }

        // 4. RSS / Reddit / вендорские ленты
        if sources.contains(.rssNews) {
            let mentions = await RSSFeedService.fetchMentions(feedURLs: settings.customRSSFeeds)
            applyMentions(mentions)
            saveContext()
        }

        // 5. X
        if sources.contains(.xTwitter) {
            let token = settings.xBearerToken
            let nitter = settings.nitterBaseURL
            let mentions = await XMonitorService.fetchMentions(
                queries: settings.xSearchQueries,
                bearerToken: token.isEmpty ? nil : token,
                nitterBaseURL: nitter.isEmpty ? nil : nitter
            )
            applyMentions(mentions)
            saveContext()
        }

        // 6. GitHub Discovery (раз в 10 минут)
        if sources.contains(.githubDiscovery), isDue(lastDiscoveryRun, every: 600) {
            let result = await GitHubMonitorService.discover(token: githubToken)
            applyDiscoveredRepos(result.repos)
            if let error = result.error { errors.append(error) }
            lastDiscoveryRun = Date()
            saveContext()
        }

        // 7. GitHub Releases (раз в 20 минут)
        if sources.contains(.githubReleases), isDue(lastReleasesRun, every: 1200) {
            let result = await GitHubMonitorService.fetchReleases(repos: settings.watchedGitHubRepos, token: githubToken)
            applyReleases(result.releases)
            if let error = result.error { errors.append(error) }
            lastReleasesRun = Date()
            saveContext()
        }

        // 8. Дозагрузка данных NVD для CVE, найденных в новостях/соцсетях/GitHub
        if sources.contains(.nvd) {
            await enrichFromNVD(limit: 2)
            saveContext()
        }

        // 9. EPSS
        if sources.contains(.epss) {
            do {
                try await applyEPSS()
            } catch {
                errors.append("EPSS: \(error.localizedDescription)")
            }
            saveContext()
        }

        // 10. PoC / Exploit
        if sources.contains(.githubPoCSearch) || sources.contains(.exploitDB)
            || sources.contains(.nucleiTemplates) || sources.contains(.metasploit) {
            await fetchMissingPoCs(token: githubToken)
            saveContext()
        }

        // 11. Производные данные и уведомления
        refreshDerivedData()
        evaluateNotifications()

        statusMessages = errors
        lastRunDate = .now
    }

    private func isDue(_ last: Date?, every seconds: TimeInterval) -> Bool {
        guard let last else { return true }
        return Date().timeIntervalSince(last) >= seconds
    }

    private func saveContext() {
        do {
            try modelContext.save()
        } catch {
            print("Ошибка сохранения SwiftData: \(error)")
        }
    }

    private func existingItem(cveID: String) -> CVEItem? {
        let descriptor = FetchDescriptor<CVEItem>(predicate: #Predicate { $0.cveID == cveID })
        return try? modelContext.fetch(descriptor).first
    }

    // MARK: - Упоминания (дедупликация источников)

    @discardableResult
    private func addMention(
        to item: CVEItem,
        url: String,
        title: String,
        kind: SourceKind? = nil,
        occurredAt: Date?,
        isSignal: Bool
    ) -> Bool {
        guard !url.isEmpty else { return false }
        if item.mentions.contains(where: { $0.url == url }) { return false }

        let now = Date()
        let occurred = min(occurredAt ?? now, now)
        let record = MentionRecord(
            url: url,
            title: title,
            kind: kind ?? SourceKind.classify(urlString: url),
            occurredAt: occurred,
            isSignal: isSignal
        )
        modelContext.insert(record)
        record.cve = item
        return true
    }

    // MARK: - Слияние данных

    private func upsert(_ newItem: CVEItem, authoritative: Bool, insertIfMissing: Bool) {
        let target: CVEItem

        if let existing = existingItem(cveID: newItem.cveID) {
            if existing.summary.isEmpty, !newItem.summary.isEmpty { existing.summary = newItem.summary }
            if (existing.title.isEmpty || existing.title == existing.cveID), !newItem.title.isEmpty { existing.title = newItem.title }

            if let score = newItem.cvssScore, authoritative || existing.cvssScore == nil {
                existing.cvssScore = score
                existing.cvssVector = newItem.cvssVector ?? existing.cvssVector
            }
            if authoritative {
                if !newItem.summary.isEmpty { existing.summary = newItem.summary }
                if newItem.vendor != nil { existing.vendor = newItem.vendor }
                if newItem.product != nil { existing.product = newItem.product }
                if !newItem.cpeRaw.isEmpty { existing.cpeRaw = newItem.cpeRaw }
                if !newItem.cwesRaw.isEmpty { existing.cwesRaw = newItem.cwesRaw }
            } else {
                if existing.vendor == nil { existing.vendor = newItem.vendor }
                if existing.product == nil { existing.product = newItem.product }
                if existing.cwesRaw.isEmpty { existing.cwesRaw = newItem.cwesRaw }
            }
            if existing.publishedDate == nil { existing.publishedDate = newItem.publishedDate }
            if let modified = newItem.lastModifiedDate { existing.lastModifiedDate = modified }
            for tag in newItem.tags { existing.addTagIfMissing(tag) }
            target = existing
        } else {
            let isRecent = (newItem.publishedDate ?? .distantPast) > Date().addingTimeInterval(-14 * 86400)
            guard insertIfMissing || isRecent else { return }
            applyWatchedKeywordTags(to: newItem)
            modelContext.insert(newItem)
            target = newItem
        }

        for url in newItem.sourceURLs {
            addMention(to: target, url: url, title: "", occurredAt: newItem.publishedDate, isSignal: false)
        }
    }

    private func applyWatchedKeywordTags(to item: CVEItem) {
        let haystack = (item.title + " " + item.summary + " " + (item.vendor ?? "") + " " + (item.product ?? "")).lowercased()
        for keyword in settings.watchedKeywords {
            let lowered = keyword.lowercased()
            if !lowered.isEmpty, haystack.contains(lowered) {
                item.addTagIfMissing(lowered)
            }
        }
    }

    private func applyKEV(entries: [CISAKEVService.Entry]) {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        let catalogURL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

        for entry in entries {
            let dueDate = entry.dueDate.flatMap { formatter.date(from: $0) }
            let addedDate = entry.dateAdded.flatMap { formatter.date(from: $0) }
            let ransomware = entry.knownRansomwareCampaignUse == "Known"

            let item: CVEItem
            if let existing = existingItem(cveID: entry.cveID) {
                existing.isKEV = true
                existing.kevDueDate = dueDate
                existing.kevDateAdded = addedDate
                existing.addTagIfMissing("kev")
                if existing.summary.isEmpty { existing.summary = entry.shortDescription ?? "" }
                if existing.vendor == nil { existing.vendor = entry.vendorProject }
                if existing.product == nil { existing.product = entry.product }
                item = existing
            } else {
                let created = CVEItem(
                    cveID: entry.cveID,
                    title: entry.vulnerabilityName ?? entry.cveID,
                    summary: entry.shortDescription ?? "",
                    vendor: entry.vendorProject,
                    product: entry.product,
                    publishedDate: addedDate,
                    isKEV: true,
                    kevDueDate: dueDate,
                    kevDateAdded: addedDate,
                    tags: ["kev"]
                )
                applyWatchedKeywordTags(to: created)
                modelContext.insert(created)
                item = created
            }
            if ransomware { item.addTagIfMissing("ransomware") }
            addMention(to: item, url: catalogURL, title: "CISA KEV", kind: .cisa, occurredAt: addedDate, isSignal: false)
        }
    }

    private func applyMentions(_ mentions: [RSSMention]) {
        for mention in mentions {
            for cveID in mention.cveIDs {
                let item: CVEItem
                if let existing = existingItem(cveID: cveID) {
                    if existing.summary.isEmpty { existing.summary = mention.articleSummary }
                    item = existing
                } else {
                    let created = CVEItem(
                        cveID: cveID,
                        title: mention.articleTitle,
                        summary: mention.articleSummary,
                        publishedDate: nil,
                        tags: []
                    )
                    applyWatchedKeywordTags(to: created)
                    modelContext.insert(created)
                    item = created
                }
                if mention.kind != .other { item.addTagIfMissing(mention.kind.rawValue) }
                addMention(
                    to: item,
                    url: mention.articleURL,
                    title: mention.articleTitle,
                    kind: mention.kind,
                    occurredAt: mention.publishedDate,
                    isSignal: true
                )
            }
        }
    }

    private func applyDiscoveredRepos(_ repos: [DiscoveredRepo]) {
        for repo in repos {
            for cveID in repo.cveIDs.prefix(3) {
                let item: CVEItem
                if let existing = existingItem(cveID: cveID) {
                    item = existing
                } else {
                    // Неизвестный CVE создаём только при высокой уверенности в PoC.
                    guard repo.confidence >= 55 else { continue }
                    let created = CVEItem(
                        cveID: cveID,
                        title: cveID,
                        summary: repo.description ?? "",
                        tags: ["github"]
                    )
                    applyWatchedKeywordTags(to: created)
                    modelContext.insert(created)
                    item = created
                }

                if !item.pocs.contains(where: { $0.url == repo.url }) {
                    let poc = PoCItem(
                        url: repo.url,
                        title: repo.fullName,
                        sourceType: .github,
                        starCount: repo.stars,
                        author: repo.owner,
                        publishedDate: repo.createdAt,
                        confidence: repo.confidence,
                        isExploit: repo.isExploit,
                        topics: repo.topics,
                        analysisNote: repo.reasons.joined(separator: ", ")
                    )
                    modelContext.insert(poc)
                    poc.cve = item
                }
                addMention(to: item, url: repo.url, title: repo.fullName, kind: .github, occurredAt: repo.createdAt, isSignal: true)
            }
        }
    }

    private func applyReleases(_ releases: [ReleaseInfo]) {
        for info in releases {
            let url = info.url
            let descriptor = FetchDescriptor<ReleaseItem>(predicate: #Predicate { $0.url == url })
            let exists = (try? modelContext.fetch(descriptor).first) != nil

            if !exists {
                let release = ReleaseItem(
                    url: info.url,
                    repo: info.repo,
                    tag: info.tag,
                    name: info.name,
                    publishedAt: info.publishedAt,
                    bodyExcerpt: info.body,
                    mentionsSecurity: info.mentionsSecurity,
                    cveIDs: info.cveIDs
                )
                modelContext.insert(release)
            }

            for cveID in info.cveIDs {
                if let item = existingItem(cveID: cveID) {
                    addMention(to: item, url: info.url, title: "\(info.repo) \(info.tag)", kind: .vendor, occurredAt: info.publishedAt, isSignal: false)
                }
            }
        }
    }

    private func enrichFromNVD(limit: Int) async {
        guard let all = try? modelContext.fetch(FetchDescriptor<CVEItem>()) else { return }
        let recheckBefore = Date().addingTimeInterval(-6 * 3600)
        let key: String? = settings.nvdAPIKey.isEmpty ? nil : settings.nvdAPIKey

        let candidates = all
            .filter { $0.cvssScore == nil && ($0.nvdCheckedAt == nil || $0.nvdCheckedAt! < recheckBefore) }
            .sorted { $0.discoveredAt > $1.discoveredAt }
            .prefix(limit)

        for item in candidates {
            item.nvdCheckedAt = .now
            if let fetched = try? await NVDService.fetchByID(item.cveID, apiKey: key) {
                upsert(fetched, authoritative: true, insertIfMissing: true)
            }
        }
    }

    private func applyEPSS() async throws {
        let allItems = try modelContext.fetch(FetchDescriptor<CVEItem>())
        let ids = allItems.filter { $0.epssScore == nil }.map { $0.cveID }
        guard !ids.isEmpty else { return }

        let scores = try await EPSSService.fetchScores(for: Array(ids.prefix(300)))
        for item in allItems {
            if let score = scores[item.cveID] { item.epssScore = score }
        }
    }

    private func fetchMissingPoCs(token: String?) async {
        guard let allItems = try? modelContext.fetch(FetchDescriptor<CVEItem>()) else { return }

        let now = Date()
        let freshAfter = now.addingTimeInterval(-30 * 86400)

        let candidates = allItems
            .filter { item in
                let reference = item.publishedDate ?? item.discoveredAt
                guard reference > freshAfter else { return false }
                guard let checked = item.pocCheckedAt else { return true }
                // Свежие CVE перепроверяем часто — PoC обычно появляется в первые часы.
                let interval: TimeInterval = now.timeIntervalSince(reference) < 3 * 86400 ? 1800 : 21600
                return now.timeIntervalSince(checked) >= interval
            }
            .sorted { a, b in
                let aNew = a.pocCheckedAt == nil
                let bNew = b.pocCheckedAt == nil
                if aNew != bNew { return aNew }
                if aNew { return (a.publishedDate ?? a.discoveredAt) > (b.publishedDate ?? b.discoveredAt) }
                return (a.pocCheckedAt ?? .distantPast) < (b.pocCheckedAt ?? .distantPast)
            }
            .prefix(token == nil ? 3 : 8)

        let sources = settings.enabledSources

        for item in candidates {
            let found = await PoCAggregatorService.findAllPoCs(
                cveID: item.cveID,
                githubToken: token,
                useGitHub: sources.contains(.githubPoCSearch),
                useNuclei: sources.contains(.nucleiTemplates),
                useExploitDB: sources.contains(.exploitDB),
                useMetasploit: sources.contains(.metasploit)
            )

            var knownURLs = Set(item.pocs.map { $0.url })
            for poc in found where !knownURLs.contains(poc.url) {
                knownURLs.insert(poc.url)
                modelContext.insert(poc)
                poc.cve = item
                addMention(
                    to: item,
                    url: poc.url,
                    title: poc.title,
                    kind: poc.sourceType.sourceKind,
                    occurredAt: poc.publishedDate,
                    isSignal: poc.sourceType == .github
                )
            }
            if !item.pocs.isEmpty { item.addTagIfMissing("has-poc") }
            item.pocCheckedAt = .now
        }
    }

    // MARK: - Производные данные

    /// Теги, watchlist, достоверность источников, trending, снимки истории.
    /// Вызывается после каждого цикла и при изменении настроек.
    func refreshDerivedData() {
        guard let items = try? modelContext.fetch(FetchDescriptor<CVEItem>()) else { return }

        let now = Date()
        let entries = settings.watchlist.filter { $0.enabled }

        // Счётчики упоминаний для trending
        let cutoff = now.addingTimeInterval(-25 * 3600)
        let hourAgo = now.addingTimeInterval(-3600)
        var lastHour: [String: Int] = [:]
        var previous: [String: Int] = [:]
        let mentionDescriptor = FetchDescriptor<MentionRecord>(
            predicate: #Predicate { $0.isSignal == true && $0.occurredAt > cutoff }
        )
        if let recent = try? modelContext.fetch(mentionDescriptor) {
            for mention in recent {
                guard let id = mention.cve?.cveID else { continue }
                if mention.occurredAt > hourAgo {
                    lastHour[id, default: 0] += 1
                } else {
                    previous[id, default: 0] += 1
                }
            }
        }

        for item in items {
            // 1. Класс уязвимости и статус подтверждения
            let normalizedText = normalizeForMatch(item.title + " " + item.summary)
            for tag in VulnClassifier.classify(normalizedText: normalizedText, cwes: item.cwes) {
                item.addTagIfMissing(tag)
            }

            let kinds = Set(item.mentions.map { $0.kind })
            let confirmed = item.isKEV || item.cvssScore != nil
                || !kinds.isDisjoint(with: [.nvd, .cisa, .ghsa, .vendor])
            if confirmed {
                item.removeTag("unconfirmed")
            } else {
                item.addTagIfMissing("unconfirmed")
            }

            // 2. Поисковый индекс
            let blob = item.buildSearchBlob()
            if item.searchBlob != blob { item.searchBlob = blob }

            // 3. Watchlist
            let labels = entries
                .filter { $0.matches(item, normalizedHaystack: blob) }
                .map { $0.label }
            let labelsRaw = labels.joined(separator: ",")
            let watched = !labels.isEmpty
            if item.isWatched != watched { item.isWatched = watched }
            if item.watchLabelsRaw != labelsRaw { item.watchLabelsRaw = labelsRaw }

            // 4. Достоверность источников (noisy-OR по типам источников)
            var counts: [SourceKind: Int] = [:]
            for mention in item.mentions { counts[mention.kind, default: 0] += 1 }
            if item.isKEV { counts[.cisa, default: 0] += 1 }
            var miss = 1.0
            for (kind, count) in counts {
                let weight = settings.weight(for: kind)
                let effective = 1 - pow(1 - weight, Double(min(count, 3)))
                miss *= (1 - effective)
            }
            let confidence = counts.isEmpty ? 0 : min(0.99, 1 - miss)
            if abs(item.sourceConfidence - confidence) > 0.001 { item.sourceConfidence = confidence }

            // 5. Trending: рост упоминаний за последний час к среднечасовому фону предыдущих 24 часов
            let mentionsLastHour = lastHour[item.cveID] ?? 0
            let baseline = Double(previous[item.cveID] ?? 0) / 24.0
            var trend = 0.0
            if mentionsLastHour >= 2 {
                trend = (Double(mentionsLastHour) - baseline) / max(baseline, 1.0) * 100.0
            }
            if trend < 100 { trend = 0 }
            if item.trendScore != trend { item.trendScore = trend }
            if item.trendMentions1h != mentionsLastHour { item.trendMentions1h = mentionsLastHour }

            // 6. История изменений
            recordSnapshotIfNeeded(for: item)
        }

        saveContext()
    }

    private func recordSnapshotIfNeeded(for item: CVEItem) {
        let pocCount = item.credibleItems.count
        let exploitCount = item.credibleItems.filter { $0.isExploitGrade }.count
        let cvssText = item.cvssScore.map { String($0) } ?? "-"
        let fingerprint = "\(cvssText)|\(item.isKEV)|\(pocCount)|\(exploitCount)"
        guard fingerprint != item.fingerprint else { return }

        func format(_ value: Double?) -> String {
            value.map { String(format: "%.1f", $0) } ?? "—"
        }

        var notes: [String] = []
        if let previous = item.snapshots.max(by: { $0.takenAt < $1.takenAt }) {
            if previous.cvssScore != item.cvssScore {
                notes.append("CVSS \(format(previous.cvssScore)) → \(format(item.cvssScore))")
            }
            if previous.pocCount == 0 && pocCount > 0 {
                notes.append("PoC detected")
            } else if pocCount > previous.pocCount {
                notes.append("PoC +\(pocCount - previous.pocCount)")
            }
            if previous.exploitCount == 0 && exploitCount > 0 {
                notes.append("Exploit detected")
            }
            if !previous.isKEV && item.isKEV {
                notes.append("Added to CISA KEV")
            }
        } else {
            notes.append("Обнаружена")
        }

        let snapshot = CVESnapshot(
            cvssScore: item.cvssScore,
            epssScore: item.epssScore,
            isKEV: item.isKEV,
            pocCount: pocCount,
            exploitCount: exploitCount,
            note: notes.joined(separator: ", ")
        )
        modelContext.insert(snapshot)
        snapshot.cve = item
        item.fingerprint = fingerprint
    }

    // MARK: - Уведомления

    private func isEnabled(_ kind: NotificationKind) -> Bool {
        switch kind {
        case .kev: return settings.notifyKEV
        case .exploit: return settings.notifyExploit
        case .poc: return settings.notifyPoC
        case .new: return settings.notifyNewVuln
        case .trending: return settings.notifyTrending
        }
    }

    private func hasRecentExploitActivity(_ item: CVEItem, now: Date) -> Bool {
        if item.discoveredAt > now.addingTimeInterval(-6 * 3600) { return true }
        return item.credibleItems.contains { $0.eventDate > now.addingTimeInterval(-72 * 3600) }
    }

    private func evaluateNotifications() {
        let now = Date()
        let isBaseline = !UserDefaults.standard.bool(forKey: baselineKey)
        let cutoff = now.addingTimeInterval(-30 * 86400)

        let descriptor = FetchDescriptor<CVEItem>(predicate: #Predicate { $0.discoveredAt > cutoff })
        guard let items = try? modelContext.fetch(descriptor) else { return }

        var sent = 0
        for item in items.sorted(by: { ($0.cvssScore ?? 0) > ($1.cvssScore ?? 0) }) {
            if settings.watchlistOnly && !item.isWatched { continue }
            if item.sourceConfidence < settings.minSourceConfidenceForNotification { continue }

            // Порядок добавления = приоритет заголовка уведомления.
            var kinds: [NotificationKind] = []
            if item.isKEV, !item.hasNotified("kev") { kinds.append(.kev) }
            if item.hasExploit, !item.hasNotified("exploit") { kinds.append(.exploit) }
            if item.hasPoC, !item.hasNotified("poc") { kinds.append(.poc) }
            if let score = item.cvssScore, score >= settings.minCVSSForNotification,
               !item.hasNotified("new"), item.discoveredAt > now.addingTimeInterval(-7 * 86400) {
                kinds.append(.new)
            }
            if item.trendScore >= 300, item.trendMentions1h >= 3, !item.hasNotified("trending") {
                kinds.append(.trending)
            }
            guard !kinds.isEmpty else { continue }

            // Дедупликация: одно уведомление на CVE, остальные поводы помечаем обработанными.
            for kind in kinds { item.markNotified(kind.rawValue) }
            if isBaseline { continue }

            let allowed = kinds.filter { kind in
                guard isEnabled(kind) else { return false }
                if kind == .poc || kind == .exploit { return hasRecentExploitActivity(item, now: now) }
                return true
            }
            guard let primary = allowed.first else { continue }

            // Не больше 6 баннеров за цикл.
            if sent < 6 {
                notificationManager.send(for: item, primary: primary)
                sent += 1
            }
        }

        if isBaseline { UserDefaults.standard.set(true, forKey: baselineKey) }
        saveContext()
    }
}
