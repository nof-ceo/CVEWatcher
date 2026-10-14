import SwiftUI
import SwiftData

@main
@MainActor
struct CVEWatcherApp: App {

    let modelContainer: ModelContainer
    @StateObject private var settings: AppSettings
    @StateObject private var scheduler: PollingScheduler
    @StateObject private var notificationManager: NotificationManager

    init() {
        let container: ModelContainer
        do {
            container = try ModelContainer(for: CVEItem.self, PoCItem.self, MentionRecord.self, CVESnapshot.self, ReleaseItem.self)
        } catch {
            fatalError("Не удалось создать ModelContainer: \(error)")
        }
        modelContainer = container

        let settingsInstance = AppSettings()
        let notificationManagerInstance = NotificationManager()
        // mainContext — тот же контекст, который используют @Query во View,
        // поэтому интерфейс обновляется сразу после сохранения.
        let coordinator = AggregationCoordinator(
            modelContext: container.mainContext,
            settings: settingsInstance,
            notificationManager: notificationManagerInstance
        )

        _settings = StateObject(wrappedValue: settingsInstance)
        _notificationManager = StateObject(wrappedValue: notificationManagerInstance)
        _scheduler = StateObject(wrappedValue: PollingScheduler(coordinator: coordinator, settings: settingsInstance))
    }

    var body: some Scene {
        Window("CVE Watcher", id: "main") {
            ContentView()
                .environmentObject(settings)
                .environmentObject(scheduler)
                .environmentObject(notificationManager)
                .modelContainer(modelContainer)
                .task {
                    notificationManager.requestAuthorizationIfNeeded()
                    scheduler.start()
                }
        }

        MenuBarExtra("CVE Watcher", systemImage: "shield.lefthalf.filled") {
            MenuBarView()
                .environmentObject(settings)
                .environmentObject(scheduler)
                .modelContainer(modelContainer)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(settings)
                .environmentObject(scheduler)
        }
    }
}
