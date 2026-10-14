import Foundation
import Combine

/// Запускает `AggregationCoordinator.runCycle()` с интервалом из настроек.
@MainActor
final class PollingScheduler: ObservableObject {

    let coordinator: AggregationCoordinator
    private let settings: AppSettings
    private var loopTask: Task<Void, Never>?

    @Published var isActive = false

    init(coordinator: AggregationCoordinator, settings: AppSettings) {
        self.coordinator = coordinator
        self.settings = settings
    }

    func start() {
        guard loopTask == nil else { return }
        isActive = true

        loopTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.coordinator.runCycle()
                let interval = max(30, self.settings.pollingIntervalSeconds)
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            }
        }
    }

    func stop() {
        loopTask?.cancel()
        loopTask = nil
        isActive = false
    }

    /// Внеочередной запуск (кнопка "Обновить сейчас").
    func runNow() {
        Task { await coordinator.runCycle() }
    }
}
