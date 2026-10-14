import SwiftUI
import SwiftData

enum SidebarFilter: Hashable {
    case all
    case watchlist
    case exploitable
    case trending
    case kev
    case favorites
    case releases
    case tag(String)
}

struct ContentView: View {
    @EnvironmentObject private var scheduler: PollingScheduler
    @EnvironmentObject private var notificationManager: NotificationManager
    @Environment(\.modelContext) private var modelContext

    @State private var selectedFilter: SidebarFilter = .all
    @State private var selectedItem: CVEItem?
    @State private var searchText = ""

    var body: some View {
        NavigationSplitView {
            SidebarView(selectedFilter: $selectedFilter)
        } content: {
            contentColumn
                .navigationSplitViewColumnWidth(min: 380, ideal: 460)
        } detail: {
            if let selectedItem {
                CVEDetailView(item: selectedItem)
            } else {
                ContentUnavailableView(
                    "Выберите уязвимость",
                    systemImage: "shield.lefthalf.filled",
                    description: Text(scheduler.isActive ? "Список обновляется автоматически в фоне." : "Фоновое обновление остановлено.")
                )
            }
        }
        .frame(minWidth: 1050, minHeight: 560)
        .toolbar {
            ToolbarItem {
                Button {
                    scheduler.runNow()
                } label: {
                    Label("Обновить сейчас", systemImage: "arrow.clockwise")
                }
            }
            ToolbarItem {
                SettingsLink {
                    Label("Настройки", systemImage: "gearshape")
                }
            }
        }
        .onChange(of: notificationManager.pendingCVEID) { _, newValue in
            guard let id = newValue else { return }
            let descriptor = FetchDescriptor<CVEItem>(predicate: #Predicate { $0.cveID == id })
            if let item = try? modelContext.fetch(descriptor).first {
                selectedFilter = .all
                searchText = ""
                selectedItem = item
            }
            notificationManager.pendingCVEID = nil
        }
    }

    @ViewBuilder
    private var contentColumn: some View {
        switch selectedFilter {
        case .releases:
            ReleasesView()
        case .exploitable:
            ExploitableView(searchText: $searchText, selectedItem: $selectedItem)
        default:
            CVEListView(filter: selectedFilter, searchText: $searchText, selectedItem: $selectedItem)
        }
    }
}
