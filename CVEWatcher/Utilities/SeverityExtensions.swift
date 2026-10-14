import SwiftUI

extension CVEItem {
    var severityColor: Color {
        guard let score = cvssScore else { return .gray }
        switch score {
        case 9...10: return .red
        case 7..<9: return .orange
        case 4..<7: return .yellow
        case 0.1..<4: return .green
        default: return .gray
        }
    }
}

extension Date {
    var relativeDescription: String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "ru_RU")
        formatter.unitsStyle = .short
        return formatter.localizedString(for: self, relativeTo: .now)
    }
}
