import Foundation

enum WatchKind: String, Codable, CaseIterable, Identifiable {
    case vendor, product, technology, cwe, cvss

    var id: String { rawValue }

    var title: String {
        switch self {
        case .vendor: return "Вендор"
        case .product: return "Продукт"
        case .technology: return "Технология"
        case .cwe: return "CWE"
        case .cvss: return "CVSS ≥"
        }
    }
}

/// Одна подписка в watchlist. Подписки объединяются по ИЛИ.
struct WatchEntry: Codable, Identifiable, Hashable {
    var id: String
    var kind: WatchKind
    var value: String
    /// Слова для сопоставления (если пусто — используется `value`).
    var keywords: [String]
    /// Дополнительный фильтр: CVSS не ниже (0 — без фильтра). Для `.cvss` не используется.
    var minCVSS: Double
    var enabled: Bool
    var isCatalog: Bool

    init(
        id: String = UUID().uuidString,
        kind: WatchKind,
        value: String,
        keywords: [String] = [],
        minCVSS: Double = 0,
        enabled: Bool = true,
        isCatalog: Bool = false
    ) {
        self.id = id
        self.kind = kind
        self.value = value
        self.keywords = keywords
        self.minCVSS = minCVSS
        self.enabled = enabled
        self.isCatalog = isCatalog
    }

    var label: String {
        kind == .cvss ? "CVSS ≥ \(value)" : value
    }

    func matches(_ item: CVEItem, normalizedHaystack: String) -> Bool {
        if kind != .cvss, minCVSS > 0 {
            guard let score = item.cvssScore, score >= minCVSS else { return false }
        }

        switch kind {
        case .cvss:
            guard let score = item.cvssScore,
                  let threshold = Double(value.replacingOccurrences(of: ",", with: ".")) else { return false }
            return score >= threshold

        case .cwe:
            let digits = value.filter { $0.isNumber }
            guard !digits.isEmpty else { return false }
            return item.cwes.contains("CWE-\(digits)")

        case .vendor, .product, .technology:
            let terms = keywords.isEmpty ? [value] : keywords
            for term in terms {
                let normalized = normalizeForMatch(term)
                if normalized.trimmingCharacters(in: .whitespaces).isEmpty { continue }
                if normalizedHaystack.contains(normalized) { return true }
            }
            return false
        }
    }
}

/// Готовый каталог популярных вендоров/технологий.
enum WatchCatalog {
    static let entries: [WatchEntry] = [
        make("apple", "Apple", .vendor, ["apple", "macos", "ios", "ipados", "safari", "webkit", "watchos", "tvos", "visionos"]),
        make("microsoft", "Microsoft", .vendor, ["microsoft", "windows", "exchange server", "sharepoint", "azure", "active directory", "hyper-v"]),
        make("apache", "Apache", .vendor, ["apache"]),
        make("cisco", "Cisco", .vendor, ["cisco", "ios xe", "nx-os", "firepower", "asa"]),
        make("linux", "Linux", .technology, ["linux kernel", "linux"]),
        make("kubernetes", "Kubernetes", .technology, ["kubernetes", "k8s", "kubelet", "kubectl"]),
        make("spring", "Spring", .technology, ["spring framework", "spring boot", "spring cloud", "spring security", "springframework"]),
        make("google", "Google / Chrome", .vendor, ["google", "chrome", "chromium", "android"]),
        make("fortinet", "Fortinet", .vendor, ["fortinet", "fortios", "fortigate", "fortiweb", "fortimanager"]),
        make("paloalto", "Palo Alto", .vendor, ["palo alto", "pan-os", "globalprotect"]),
        make("citrix", "Citrix", .vendor, ["citrix", "netscaler"]),
        make("vmware", "VMware", .vendor, ["vmware", "esxi", "vcenter"]),
        make("oracle", "Oracle", .vendor, ["oracle", "weblogic", "mysql"]),
        make("openssl", "OpenSSL", .technology, ["openssl"]),
        make("docker", "Docker", .technology, ["docker", "containerd", "runc"]),
        make("nginx", "Nginx", .technology, ["nginx"]),
        make("wordpress", "WordPress", .technology, ["wordpress"]),
        make("jenkins", "Jenkins", .technology, ["jenkins"]),
        make("gitlab", "GitLab", .vendor, ["gitlab"]),
        make("atlassian", "Atlassian", .vendor, ["atlassian", "confluence", "jira", "bitbucket"]),
        make("ivanti", "Ivanti", .vendor, ["ivanti", "pulse secure"]),
        make("juniper", "Juniper", .vendor, ["juniper", "junos"]),
        make("sap", "SAP", .vendor, ["sap"])
    ]

    private static func make(_ id: String, _ name: String, _ kind: WatchKind, _ keywords: [String]) -> WatchEntry {
        WatchEntry(id: "catalog:" + id, kind: kind, value: name, keywords: keywords, minCVSS: 0, enabled: false, isCatalog: true)
    }
}
