import Foundation

/// Rule-based определение класса уязвимости (rce, xss, sqli...) по описанию и CWE.
enum VulnClassifier {

    private struct Rule {
        let tag: String
        let keywords: [String]   // уже нормализованы
        let cwes: [String]
    }

    private static let rules: [Rule] = {
        let raw: [(String, [String], [String])] = [
            ("rce", ["remote code execution", "arbitrary code execution", "execute arbitrary code", "code injection",
                     "command injection", "os command", "rce", "arbitrary command"],
             ["CWE-94", "CWE-78", "CWE-77", "CWE-95"]),
            ("xss", ["cross-site scripting", "cross site scripting", "xss"], ["CWE-79"]),
            ("sqli", ["sql injection"], ["CWE-89"]),
            ("privesc", ["privilege escalation", "elevation of privilege", "escalate privileges"], ["CWE-269", "CWE-250"]),
            ("dos", ["denial of service", "dos"], ["CWE-400", "CWE-770"]),
            ("auth-bypass", ["authentication bypass", "bypass authentication", "improper authentication",
                             "missing authentication", "unauthenticated"], ["CWE-287", "CWE-306", "CWE-862"]),
            ("ssrf", ["server-side request forgery", "ssrf"], ["CWE-918"]),
            ("path-traversal", ["path traversal", "directory traversal", "local file inclusion", "arbitrary file read"],
             ["CWE-22", "CWE-23"]),
            ("xxe", ["xml external entity", "xxe"], ["CWE-611"]),
            ("csrf", ["cross-site request forgery", "csrf"], ["CWE-352"]),
            ("info-leak", ["information disclosure", "sensitive information", "information leak"], ["CWE-200", "CWE-532"]),
            ("deserialization", ["deserialization"], ["CWE-502"]),
            ("memory-corruption", ["buffer overflow", "use-after-free", "use after free", "out-of-bounds",
                                   "heap overflow", "memory corruption"], ["CWE-119", "CWE-787", "CWE-416", "CWE-125", "CWE-120"])
        ]
        return raw.map { Rule(tag: $0.0, keywords: $0.1.map { normalizeForMatch($0) }, cwes: $0.2) }
    }()

    /// `normalizedText` — результат `normalizeForMatch` для заголовка и описания.
    static func classify(normalizedText: String, cwes: [String]) -> [String] {
        var tags: [String] = []
        for rule in rules {
            if rule.cwes.contains(where: { cwes.contains($0) }) || rule.keywords.contains(where: { normalizedText.contains($0) }) {
                tags.append(rule.tag)
            }
        }
        return tags
    }
}
