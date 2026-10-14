import Foundation

enum DurationFormat {
    static func string(_ interval: TimeInterval) -> String {
        let total = Int(abs(interval))
        let minutes = total / 60
        if minutes < 1 { return "< 1 мин" }
        if minutes < 60 { return "\(minutes) мин" }
        let hours = minutes / 60
        if hours < 24 {
            let rest = minutes % 60
            return rest == 0 ? "\(hours) ч" : "\(hours) ч \(rest) мин"
        }
        let days = hours / 24
        let restHours = hours % 24
        return restHours == 0 ? "\(days) д" : "\(days) д \(restHours) ч"
    }
}
