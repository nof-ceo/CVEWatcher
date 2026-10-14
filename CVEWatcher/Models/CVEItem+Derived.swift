import Foundation

/// Глобальные пороги, которые обновляются из настроек.
enum Thresholds {
    static var minPoCConfidence: Int = 40
}

struct ChainStep: Identifiable {
    let id = UUID()
    let label: String
    let date: Date
    let approximate: Bool
    let url: String?
}

extension CVEItem {

    // MARK: - CWE / CPE

    var cwes: [String] {
        get { cwesRaw.isEmpty ? [] : cwesRaw.components(separatedBy: ",") }
        set { cwesRaw = newValue.joined(separator: ",") }
    }

    var cpePairs: [(vendor: String, product: String)] {
        cpeRaw.split(separator: "|").compactMap { pair in
            let parts = pair.split(separator: ":", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else { return nil }
            return (vendor: parts[0], product: parts[1])
        }
    }

    var displayVendor: String? {
        vendor?.replacingOccurrences(of: "_", with: " ")
    }

    var displayProduct: String? {
        product?.replacingOccurrences(of: "_", with: " ")
    }

    var productLine: String {
        [displayVendor, displayProduct].compactMap { $0 }.joined(separator: " ")
    }

    var watchLabels: [String] {
        watchLabelsRaw.isEmpty ? [] : watchLabelsRaw.components(separatedBy: ",")
    }

    // MARK: - Уведомления

    func hasNotified(_ kind: String) -> Bool {
        notifiedKindsRaw.split(separator: ",").contains { $0 == kind }
    }

    func markNotified(_ kind: String) {
        if !hasNotified(kind) {
            notifiedKindsRaw = notifiedKindsRaw.isEmpty ? kind : notifiedKindsRaw + "," + kind
        }
    }

    // MARK: - PoC / Exploit

    var credibleItems: [PoCItem] {
        pocs.filter { $0.confidence >= Thresholds.minPoCConfidence }
    }

    var hasPoC: Bool { !credibleItems.isEmpty }

    var hasExploit: Bool { credibleItems.contains { $0.isExploitGrade } }

    var hasMetasploit: Bool { pocs.contains { $0.sourceType == .metasploit } }

    /// Первый PoC с точной датой (GitHub, Exploit-DB).
    var firstPoCDate: Date? {
        credibleItems.filter { !$0.isDateApproximate }.map { $0.eventDate }.min()
    }

    /// Время от публикации CVE до первого PoC (может быть отрицательным).
    var timeToFirstPoC: TimeInterval? {
        guard let published = publishedDate, let first = firstPoCDate else { return nil }
        return first.timeIntervalSince(published)
    }

    /// Цепочка: CVE published → GitHub PoC → Exploit-DB → Metasploit → KEV.
    var exploitChain: [ChainStep] {
        var steps: [ChainStep] = []
        if let published = publishedDate {
            steps.append(ChainStep(label: "CVE опубликована", date: published, approximate: false, url: nil))
        }

        func earliest(_ type: PoCSourceType) -> PoCItem? {
            credibleItems.filter { $0.sourceType == type }.min { $0.eventDate < $1.eventDate }
        }

        if let poc = earliest(.github) {
            steps.append(ChainStep(label: "GitHub PoC", date: poc.eventDate, approximate: poc.isDateApproximate, url: poc.url))
        }
        if let poc = earliest(.nucleiTemplate) {
            steps.append(ChainStep(label: "Nuclei template", date: poc.eventDate, approximate: true, url: poc.url))
        }
        if let poc = earliest(.exploitDB) {
            steps.append(ChainStep(label: "Exploit-DB", date: poc.eventDate, approximate: poc.isDateApproximate, url: poc.url))
        }
        if let poc = earliest(.metasploit) {
            steps.append(ChainStep(label: "Metasploit", date: poc.eventDate, approximate: true, url: poc.url))
        }
        if let kev = kevDateAdded {
            steps.append(ChainStep(label: "CISA KEV", date: kev, approximate: false, url: nil))
        }
        return steps.sorted { $0.date < $1.date }
    }

    // MARK: - Trending

    var isTrending: Bool { trendScore >= 100 }

    var trendLabel: String {
        (trendScore >= 300 ? "🔥" : "↑") + " +\(Int(trendScore))%"
    }

    // MARK: - Сортировка (для Table)

    var cvssSortValue: Double { cvssScore ?? -1 }
    var pocSortValue: Int { hasPoC ? 1 : 0 }
    var exploitSortValue: Int { hasExploit ? 1 : 0 }
    var kevSortValue: Int { isKEV ? 1 : 0 }

    // MARK: - Поиск

    func buildSearchBlob() -> String {
        let source = [cveID, title, summary, vendor ?? "", product ?? "", cpeRaw, cwesRaw, tagsRaw]
            .joined(separator: " ")
        return normalizeForMatch(source)
    }
}
