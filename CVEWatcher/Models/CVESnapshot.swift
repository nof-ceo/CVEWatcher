import Foundation
import SwiftData

/// Снимок состояния CVE в момент, когда что-то изменилось (CVSS, PoC, эксплойт, KEV).
@Model
final class CVESnapshot {
    var takenAt: Date
    var cvssScore: Double?
    var epssScore: Double?
    var isKEV: Bool
    var pocCount: Int
    var exploitCount: Int
    var note: String

    var cve: CVEItem?

    init(takenAt: Date = .now, cvssScore: Double?, epssScore: Double?, isKEV: Bool, pocCount: Int, exploitCount: Int, note: String) {
        self.takenAt = takenAt
        self.cvssScore = cvssScore
        self.epssScore = epssScore
        self.isKEV = isKEV
        self.pocCount = pocCount
        self.exploitCount = exploitCount
        self.note = note
    }

    var summaryLine: String {
        var parts: [String] = []
        parts.append(cvssScore.map { "CVSS " + String(format: "%.1f", $0) } ?? "CVSS —")
        parts.append(pocCount > 0 ? "PoC detected" : "No PoC")
        if exploitCount > 0 { parts.append("Exploit detected") }
        if isKEV { parts.append("KEV") }
        return parts.joined(separator: " · ")
    }
}
