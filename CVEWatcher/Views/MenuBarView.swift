import SwiftUI
import SwiftData
import AppKit

struct MenuBarView: View {
    @EnvironmentObject private var scheduler: PollingScheduler
    @Environment(\.openWindow) private var openWindow
    @Query(sort: \CVEItem.discoveredAt, order: .reverse) private var allItems: [CVEItem]

    var body: some View {
        let trending = Array(allItems.filter { $0.isTrending }.sorted { $0.trendScore > $1.trendScore }.prefix(3))
        let exploitable = Array(allItems.filter { $0.hasExploit || $0.isKEV }.prefix(5))
        let recent = Array(allItems.prefix(6))

        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("CVE Watcher").font(.headline)
                Spacer()
                Button {
                    scheduler.runNow()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.plain)
            }
            .padding(12)

            Divider()

            if allItems.isEmpty {
                Text("Пока нет данных. Подождите первый цикл опроса или нажмите обновить.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(12)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        if !trending.isEmpty {
                            section("Trending") {
                                ForEach(trending, id: \.cveID) { item in
                                    row(item, trailing: item.trendLabel)
                                }
                            }
                        }
                        if !exploitable.isEmpty {
                            section("Exploitable") {
                                ForEach(exploitable, id: \.cveID) { item in
                                    row(item, trailing: item.hasExploit ? "exploit" : "KEV")
                                }
                            }
                        }
                        section("Недавние") {
                            ForEach(recent, id: \.cveID) { item in
                                row(item, trailing: item.cvssScore.map { String(format: "%.1f", $0) } ?? "")
                            }
                        }
                    }
                    .padding(.vertical, 8)
                }
                .frame(maxHeight: 340)
            }

            Divider()

            HStack {
                Button("Открыть окно") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                SettingsLink {
                    Text("Настройки…")
                }
                Spacer()
                Button("Выйти") {
                    NSApp.terminate(nil)
                }
            }
            .padding(12)
        }
        .frame(width: 340)
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title.uppercased())
                .font(.caption2.bold())
                .foregroundStyle(.secondary)
                .padding(.horizontal, 12)
            content()
        }
    }

    private func row(_ item: CVEItem, trailing: String) -> some View {
        HStack {
            Circle().fill(item.severityColor).frame(width: 8, height: 8)
            Text(item.cveID).font(.subheadline.bold())
            Text(item.productLine.isEmpty ? item.title : item.productLine)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
            Text(trailing).font(.caption.bold()).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
    }
}
