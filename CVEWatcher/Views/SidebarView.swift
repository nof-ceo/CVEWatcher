import SwiftUI
import SwiftData

struct SidebarView: View {
    @Binding var selectedFilter: SidebarFilter
    @EnvironmentObject private var scheduler: PollingScheduler
    @Query(sort: \CVEItem.discoveredAt, order: .reverse) private var allItems: [CVEItem]

    private var allTags: [String] {
        Array(Set(allItems.flatMap { $0.tags })).sorted()
    }

    private var optionalSelection: Binding<SidebarFilter?> {
        Binding(
            get: { selectedFilter },
            set: { newValue in
                if let newValue { selectedFilter = newValue }
            }
        )
    }

    var body: some View {
        let exploitableCount = allItems.filter { $0.hasPoC || $0.hasExploit || $0.isKEV }.count
        let trendingCount = allItems.filter { $0.isTrending }.count
        let watchCount = allItems.filter { $0.isWatched }.count

        List(selection: optionalSelection) {
            Section("Обзор") {
                Label("Все уязвимости", systemImage: "list.bullet")
                    .tag(SidebarFilter.all)
                Label("Watchlist", systemImage: "eye")
                    .badge(watchCount)
                    .tag(SidebarFilter.watchlist)
                Label("Exploitable", systemImage: "bolt.shield")
                    .badge(exploitableCount)
                    .tag(SidebarFilter.exploitable)
                Label("Trending", systemImage: "flame")
                    .badge(trendingCount)
                    .tag(SidebarFilter.trending)
                Label("KEV", systemImage: "exclamationmark.triangle.fill")
                    .tag(SidebarFilter.kev)
                Label("Избранное", systemImage: "star.fill")
                    .tag(SidebarFilter.favorites)
                Label("GitHub Releases", systemImage: "shippingbox")
                    .tag(SidebarFilter.releases)
            }

            if !allTags.isEmpty {
                Section("Теги") {
                    ForEach(allTags, id: \.self) { tag in
                        Label(tag, systemImage: "tag")
                            .tag(SidebarFilter.tag(tag))
                    }
                }
            }
        }
        .navigationSplitViewColumnWidth(min: 190, ideal: 230)
        .safeAreaInset(edge: .bottom) {
            StatusFooter(coordinator: scheduler.coordinator)
        }
    }
}

struct StatusFooter: View {
    @ObservedObject var coordinator: AggregationCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                if coordinator.isRunning {
                    ProgressView().controlSize(.small)
                    Text("Обновление…")
                } else if let date = coordinator.lastRunDate {
                    Text("Обновлено \(date.relativeDescription)")
                } else {
                    Text("Ожидание первого цикла")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            ForEach(coordinator.statusMessages, id: \.self) { message in
                Text(message)
                    .font(.caption2)
                    .foregroundStyle(.red)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(.bar)
    }
}
