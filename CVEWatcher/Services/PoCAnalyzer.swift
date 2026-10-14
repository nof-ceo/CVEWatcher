import Foundation

struct PoCAnalysis: Sendable {
    let confidence: Int
    let isExploit: Bool
    let reasons: [String]
}

/// Rule-based оценка: насколько репозиторий похож на настоящий PoC/эксплойт.
enum PoCAnalyzer {

    private static let trustedOwners: Set<String> = [
        "projectdiscovery", "rapid7", "vulhub", "offensive-security", "trickest", "nomi-sec"
    ]

    static func analyze(
        cveID: String?,
        name: String,
        description: String?,
        topics: [String],
        stars: Int,
        isFork: Bool,
        sizeKB: Int?,
        owner: String?,
        files: [String]?
    ) -> PoCAnalysis {
        var score = 0
        var reasons: [String] = []

        let lowerName = name.lowercased()
        let lowerDesc = (description ?? "").lowercased()
        let text = lowerName + " " + lowerDesc

        // 1. CVE в названии / описании
        if let cveID {
            let id = cveID.lowercased()
            if lowerName.contains(id) {
                score += 40
                reasons.append("CVE в названии")
                if lowerDesc.contains(id) { score += 5 }
            } else if lowerDesc.contains(id) {
                score += 25
                reasons.append("CVE в описании")
            }
        } else if !CVERegex.findAll(in: name).isEmpty {
            score += 40
            reasons.append("CVE в названии")
        }

        // 2. poc / exploit / rce в названии
        var nameBonus = 0
        for (word, points) in [("poc", 12), ("exploit", 12), ("rce", 8)] where lowerName.contains(word) {
            nameBonus += points
        }
        if nameBonus > 0 {
            score += min(nameBonus, 24)
            reasons.append("poc/exploit в названии")
        }

        // 3. ключевые слова в описании
        let descWords = ["exploit", "poc", "proof of concept", "rce", "remote code execution", "payload",
                         "reverse shell", "vulnerab", "unauthenticated", "privilege escalation", "weaponized"]
        let hits = descWords.filter { lowerDesc.contains($0) }.count
        if hits > 0 {
            score += min(hits * 4, 16)
            reasons.append("ключевые слова в описании (\(hits))")
        }

        // 4. темы репозитория
        let topicWords = ["poc", "exploit", "cve", "vulnerability", "rce", "security", "pentest", "hacking"]
        let topicHits = topics.filter { topic in
            topicWords.contains { topic.lowercased().contains($0) }
        }.count
        if topicHits > 0 {
            score += min(topicHits * 4, 12)
            reasons.append("темы репозитория")
        }

        // 5. известные авторы
        if trustedOwners.contains((owner ?? "").lowercased()) {
            score += 15
            reasons.append("известный автор")
        }

        // 6. файлы в корне (если анализировали)
        if let files {
            let names = files.map { $0.lowercased() }
            if names.contains(where: { $0.contains("exploit") || $0.contains("poc") }) {
                score += 15
                reasons.append("файл exploit/poc")
            }
            if names.contains(where: { $0.hasSuffix(".yaml") && $0.contains("cve-") }) {
                score += 10
                reasons.append("nuclei-шаблон")
            }
            if names.contains(where: { $0 == "dockerfile" || $0.hasPrefix("docker-compose") }) {
                score += 5
                reasons.append("лабораторная среда (Docker)")
            }
        }

        // 7. звёзды
        if stars > 0 {
            let bonus = min(10, Int(log2(Double(stars + 1)) * 2))
            if bonus > 0 {
                score += bonus
                reasons.append("звёзды: \(stars)")
            }
        }

        // 8. штрафы
        if isFork {
            score -= 10
            reasons.append("форк")
        }
        if let sizeKB, sizeKB == 0 {
            score -= 25
            reasons.append("пустой репозиторий")
        }

        score = max(0, min(100, score))

        let exploitWords = ["exploit", "weaponized", "reverse shell", "metasploit"]
        var isExploit = exploitWords.contains { text.contains($0) } && score >= 55
        if let files, files.contains(where: { $0.lowercased().contains("exploit") }), score >= 50 {
            isExploit = true
        }

        return PoCAnalysis(confidence: score, isExploit: isExploit, reasons: reasons)
    }
}
