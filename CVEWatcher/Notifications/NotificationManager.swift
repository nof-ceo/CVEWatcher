import Foundation
import Combine
import AppKit
import UserNotifications

/// Виды уведомлений. Порядок = приоритет (одно уведомление на CVE за цикл).
enum NotificationKind: String {
    case kev, exploit, poc, new, trending
}

final class NotificationManager: NSObject, ObservableObject, UNUserNotificationCenterDelegate {

    /// CVE, по уведомлению о котором кликнул пользователь — ContentView её выберет.
    @Published var pendingCVEID: String?

    override init() {
        super.init()
        UNUserNotificationCenter.current().delegate = self
    }

    func requestAuthorizationIfNeeded() {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            if settings.authorizationStatus == .notDetermined {
                UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, error in
                    if let error {
                        print("Ошибка запроса разрешения на уведомления: \(error)")
                    }
                }
            }
        }
    }

    func send(for item: CVEItem, primary: NotificationKind) {
        let content = UNMutableNotificationContent()

        switch primary {
        case .kev:
            content.title = "🔥 CVE added to CISA KEV"
        case .exploit:
            content.title = "🚨 Exploit detected"
        case .poc:
            content.title = "⚠️ PoC detected for \(item.cveID)"
        case .new:
            let score = item.cvssScore ?? 0
            if score >= 9 {
                content.title = "🔴 New critical vulnerability"
            } else if score >= 7 {
                content.title = "🟠 New high-severity vulnerability"
            } else {
                content.title = "🟡 New vulnerability"
            }
        case .trending:
            content.title = "📈 Trending: \(Int(item.trendScore))% mentions growth"
        }

        var subtitleParts = [item.cveID]
        if let score = item.cvssScore { subtitleParts.append("CVSS " + String(format: "%.1f", score)) }
        content.subtitle = subtitleParts.joined(separator: " · ")

        var facts: [String] = []
        if item.isKEV && primary != .kev { facts.append("KEV") }
        if item.hasExploit && primary != .exploit { facts.append("Exploit available") }
        if item.hasPoC && primary != .poc && primary != .exploit { facts.append("PoC available") }
        if item.sourceConfidence > 0 {
            facts.append("Confidence \(Int(item.sourceConfidence * 100))%")
        }

        var lines: [String] = []
        if !facts.isEmpty { lines.append(facts.joined(separator: " · ")) }
        if !item.productLine.isEmpty {
            lines.append(item.productLine)
        } else if !item.title.isEmpty, item.title != item.cveID {
            lines.append(String(item.title.prefix(100)))
        }
        content.body = lines.joined(separator: "\n")
        content.sound = .default
        content.threadIdentifier = item.cveID
        content.userInfo = ["cveID": item.cveID]

        let identifier = "\(item.cveID)-\(primary.rawValue)-\(Int(Date().timeIntervalSince1970))"
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                print("Не удалось отправить уведомление: \(error)")
            }
        }
    }

    // Показывать баннер, даже если приложение на переднем плане.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    // Клик по уведомлению — открыть приложение и выбрать CVE.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        if let cveID = response.notification.request.content.userInfo["cveID"] as? String {
            DispatchQueue.main.async {
                self.pendingCVEID = cveID
                NSApp.activate(ignoringOtherApps: true)
            }
        }
        completionHandler()
    }
}
