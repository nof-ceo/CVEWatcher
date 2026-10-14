import SwiftUI
import SwiftData

struct CVEListView: View {
    let filter: SidebarFilter
    @Binding var searchText: String
    @Binding var selectedItem: CVEItem?

    @EnvironmentObject private var settings: AppSettings
    @Query(sort: \CVEItem.discoveredAt, order: .reverse) private var allItems: [CVEItem]
    @State private var showHelp = false

    var body: some View {
        let compiled = SearchQuery.compile(searchText)
        let items = ItemFilter.apply(allItems, filter: filter, query: compiled.query, watchlistOnly: settings.watchlistOnly)

        List(items, selection: $selectedItem) { item in
            CVERowView(item: item)
                .tag(item)
                .contextMenu {
                    Button(item.isFavorite ? "Убрать из избранного" : "В избранное") {
                        item.isFavorite.toggle()
                    }
                }
        }
        .searchable(text: $searchText, prompt: "Поиск: rce AND poc AND cvss >= 8")
        .navigationSubtitle("\(items.count) из \(allItems.count)")
        .safeAreaInset(edge: .top) {
            if let error = compiled.error {
                Text("Запрос: \(error). Выполнен обычный поиск.")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(.bar)
            }
        }
        .overlay {
            if items.isEmpty {
                if searchText.isEmpty {
                    ContentUnavailableView(
                        "Пока пусто",
                        systemImage: "tray",
                        description: Text("Данные появятся после первого цикла опроса. Статус виден внизу боковой панели.")
                    )
                } else {
                    ContentUnavailableView.search(text: searchText)
                }
            }
        }
        .toolbar {
            ToolbarItem {
                Button {
                    showHelp.toggle()
                } label: {
                    Label("Синтаксис поиска", systemImage: "questionmark.circle")
                }
                .popover(isPresented: $showHelp) {
                    SearchHelpView()
                }
            }
        }
    }
}

struct CVERowView: View {
    @Bindable var item: CVEItem

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(item.severityColor)
                .frame(width: 10, height: 10)
                .padding(.top, 4)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(item.cveID).font(.headline)
                    if item.isKEV {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .help("CISA KEV: эксплуатируется в атаках")
                    }
                    if item.hasExploit {
                        Image(systemName: "bolt.fill")
                            .foregroundStyle(.red)
                            .help("Найден эксплойт")
                    } else if item.hasPoC {
                        Image(systemName: "chevron.left.forwardslash.chevron.right")
                            .foregroundStyle(.blue)
                            .help("Найден PoC")
                    }
                    if item.isWatched {
                        Image(systemName: "eye.fill")
                            .foregroundStyle(.teal)
                            .help("Watchlist: \(item.watchLabels.joined(separator: ", "))")
                    }
                    Spacer()
                    Button {
                        item.isFavorite.toggle()
                    } label: {
                        Image(systemName: item.isFavorite ? "star.fill" : "star")
                            .foregroundStyle(item.isFavorite ? .yellow : .secondary)
                    }
                    .buttonStyle(.plain)
                }

                Text(item.title.isEmpty ? item.summary : item.title)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)

                HStack(spacing: 8) {
                    if let score = item.cvssScore {
                        Text("CVSS \(String(format: "%.1f", score))")
                            .font(.caption)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(item.severityColor.opacity(0.2))
                            .clipShape(Capsule())
                    }
                    if item.isTrending {
                        Text(item.trendLabel)
                            .font(.caption.bold())
                            .foregroundStyle(.orange)
                    }
                    if item.sourceConfidence > 0 {
                        Text("conf \(Int(item.sourceConfidence * 100))%")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if let date = item.publishedDate {
                        Text(date.relativeDescription)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }
}
