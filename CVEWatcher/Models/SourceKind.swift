import Foundation

/// Тип источника. Используется для дедупликации, подсчёта достоверности и trending.
enum SourceKind: String, CaseIterable, Codable, Identifiable {
    case vendor, cisa, nvd, ghsa, github, exploitDB, metasploit, nuclei, news, reddit, x, forum, other

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .vendor: return "Vendor advisory"
        case .cisa: return "CISA"
        case .nvd: return "NVD"
        case .ghsa: return "GitHub Advisory"
        case .github: return "GitHub"
        case .exploitDB: return "Exploit-DB"
        case .metasploit: return "Metasploit"
        case .nuclei: return "Nuclei"
        case .news: return "Новости"
        case .reddit: return "Reddit"
        case .x: return "X"
        case .forum: return "Форумы"
        case .other: return "Прочее"
        }
    }

    var icon: String {
        switch self {
        case .vendor: return "building.2"
        case .cisa: return "shield.checkered"
        case .nvd: return "externaldrive.connected.to.line.below"
        case .ghsa: return "exclamationmark.shield"
        case .github: return "chevron.left.forwardslash.chevron.right"
        case .exploitDB: return "ladybug"
        case .metasploit: return "bolt.shield"
        case .nuclei: return "atom"
        case .news: return "newspaper"
        case .reddit: return "bubble.left.and.bubble.right"
        case .x: return "at"
        case .forum: return "person.3"
        case .other: return "link"
        }
    }

    /// Коэффициенты по умолчанию (пользователь может изменить в настройках).
    var defaultWeight: Double {
        switch self {
        case .vendor: return 1.0
        case .cisa: return 1.0
        case .nvd: return 0.95
        case .ghsa: return 0.9
        case .github: return 0.8
        case .exploitDB: return 0.8
        case .metasploit: return 0.9
        case .nuclei: return 0.85
        case .news: return 0.6
        case .reddit: return 0.5
        case .x: return 0.4
        case .forum: return 0.3
        case .other: return 0.3
        }
    }

    private static let vendorDomains = [
        "microsoft.com", "apple.com", "cisco.com", "apache.org", "redhat.com", "ubuntu.com", "debian.org",
        "oracle.com", "vmware.com", "broadcom.com", "adobe.com", "android.com", "mozilla.org", "fortinet.com",
        "paloaltonetworks.com", "citrix.com", "f5.com", "ivanti.com", "sap.com", "ibm.com", "kernel.org",
        "openssl.org", "spring.io", "kubernetes.io", "atlassian.com", "jenkins.io", "gitlab.com", "sonicwall.com",
        "juniper.net", "zyxel.com", "dell.com", "hp.com", "intel.com", "amd.com", "nvidia.com", "qualcomm.com",
        "samsung.com", "siemens.com", "cloudflare.com", "docker.com", "hashicorp.com", "php.net", "python.org",
        "nginx.org", "openssh.com", "samba.org", "suse.com", "freebsd.org", "netapp.com", "trendmicro.com",
        "chromium.org", "chrome.com", "wordpress.org", "drupal.org", "joomla.org", "mysql.com", "postgresql.org"
    ]

    private static let newsDomains = [
        "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com", "threatpost.com", "securityweek.com",
        "darkreading.com", "therecord.media", "theregister.com", "arstechnica.com", "portswigger.net",
        "blogspot.com", "feedburner.com", "helpnetsecurity.com", "cyberscoop.com", "securityaffairs.com",
        "zerodayinitiative.com", "rapid7.com", "tenable.com", "qualys.com", "watchtowr.com", "assetnote.io",
        "wired.com", "zdnet.com", "securityboulevard.com", "cybersecuritynews.com", "gbhackers.com"
    ]

    private static let forumDomains = [
        "news.ycombinator.com", "lobste.rs", "stackexchange.com", "stackoverflow.com", "0x00sec.org",
        "xss.is", "exploit.in", "breachforums.st", "hackforums.net", "habr.com"
    ]

    static func classify(urlString: String) -> SourceKind {
        guard let url = URL(string: urlString), let rawHost = url.host?.lowercased() else { return .other }
        let host = rawHost.hasPrefix("www.") ? String(rawHost.dropFirst(4)) : rawHost
        let path = url.path.lowercased()

        func matches(_ domains: [String]) -> Bool {
            domains.contains { host == $0 || host.hasSuffix("." + $0) }
        }

        if matches(["nvd.nist.gov"]) { return .nvd }
        if matches(["cisa.gov"]) { return .cisa }
        if matches(["exploit-db.com"]) { return .exploitDB }
        if matches(["github.com", "githubusercontent.com"]) {
            if path.contains("metasploit-framework") { return .metasploit }
            if path.contains("nuclei-templates") { return .nuclei }
            if path.contains("/advisories/") || path.contains("ghsa-") { return .ghsa }
            return .github
        }
        if matches(["reddit.com", "redd.it"]) { return .reddit }
        if matches(["twitter.com", "x.com", "t.co"]) || host.contains("nitter") { return .x }
        if matches(vendorDomains) || host.hasPrefix("security.") || host.contains("psirt") || host.hasPrefix("msrc") {
            return .vendor
        }
        if matches(newsDomains) { return .news }
        if host.contains("forum") || matches(forumDomains) { return .forum }
        return .other
    }
}
