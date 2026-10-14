import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var settings: AppSettings
    @EnvironmentObject private var scheduler: PollingScheduler

    @State private var nvdAPIKey = ""
    @State private var githubToken = ""
    @State private var xBearerToken = ""
    @State private var savedMessage = ""

    @State private var newKeyword = ""
    @State private var newFeedURL = ""
    @State private var newXQuery = ""
    @State private var newRepo = ""

    @State private var newWatchKind: WatchKind = .vendor
    @State private var newWatchValue = ""
    @State private var newWatchMinCVSS = 0.0

    var body: some View {
        TabView {
            generalTab.tabItem { Label("Общие", systemImage: "gearshape") }
            sourcesTab.tabItem { Label("Источники", systemImage: "antenna.radiowaves.left.and.right") }
            watchlistTab.tabItem { Label("Watchlist", systemImage: "eye") }
            reliabilityTab.tabItem { Label("Достоверность", systemImage: "checkmark.seal") }
            notificationsTab.tabItem { Label("Уведомления", systemImage: "bell") }
            tokensTab.tabItem { Label("Токены", systemImage: "key") }
        }
        .frame(width: 680, height: 580)
        .onAppear {
            nvdAPIKey = settings.nvdAPIKey
            githubToken = settings.githubToken
            xBearerToken = settings.xBearerToken
        }
    }

    private func refreshDerived() {
        scheduler.coordinator.refreshDerivedData()
    }

    // MARK: - Общие

    private var generalTab: some View {
        Form {
            Section("Интервал опроса") {
                Slider(value: $settings.pollingIntervalSeconds, in: 30...900, step: 30) {
                    Text("Интервал")
                } minimumValueLabel: {
                    Text("30с")
                } maximumValueLabel: {
                    Text("15м")
                }
                Text("Текущий интервал: \(Int(settings.pollingIntervalSeconds)) секунд. GitHub Discovery выполняется раз в 10 минут, Releases — раз в 20.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Ключевые слова для автотегов") {
                HStack {
                    TextField("например: apache, cisco, linux kernel", text: $newKeyword)
                    Button("Добавить") {
                        let trimmed = newKeyword.trimmingCharacters(in: .whitespaces)
                        guard !trimmed.isEmpty else { return }
                        settings.watchedKeywords.append(trimmed)
                        newKeyword = ""
                    }
                }
                ForEach(settings.watchedKeywords, id: \.self) { keyword in
                    HStack {
                        Text(keyword)
                        Spacer()
                        Button(role: .destructive) {
                            settings.watchedKeywords.removeAll { $0 == keyword }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Источники

    private var sourcesTab: some View {
        Form {
            Section("Включённые источники") {
                ForEach(DataSource.allCases) { source in
                    Toggle(source.rawValue, isOn: Binding(
                        get: { settings.enabledSources.contains(source) },
                        set: { isOn in
                            if isOn { settings.enabledSources.insert(source) }
                            else { settings.enabledSources.remove(source) }
                        }
                    ))
                }
            }

            Section("GitHub Releases: отслеживаемые репозитории") {
                HStack {
                    TextField("owner/repo, например apache/tomcat", text: $newRepo)
                    Button("Добавить") {
                        let trimmed = newRepo.trimmingCharacters(in: .whitespaces)
                        guard trimmed.split(separator: "/").count == 2 else { return }
                        settings.watchedGitHubRepos.append(trimmed)
                        newRepo = ""
                    }
                }
                ForEach(settings.watchedGitHubRepos, id: \.self) { repo in
                    HStack {
                        Text(repo).font(.caption)
                        Spacer()
                        Button(role: .destructive) {
                            settings.watchedGitHubRepos.removeAll { $0 == repo }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }
            }

            Section("RSS, Reddit и вендорские ленты") {
                HStack {
                    TextField("URL ленты", text: $newFeedURL)
                    Button("Добавить") {
                        let trimmed = newFeedURL.trimmingCharacters(in: .whitespaces)
                        guard !trimmed.isEmpty else { return }
                        settings.customRSSFeeds.append(trimmed)
                        newFeedURL = ""
                    }
                }
                ForEach(settings.customRSSFeeds, id: \.self) { feed in
                    HStack {
                        Text(feed).font(.caption).lineLimit(1)
                        Spacer()
                        Button(role: .destructive) {
                            settings.customRSSFeeds.removeAll { $0 == feed }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }
                Text("Для любого сабреддита: https://www.reddit.com/r/НАЗВАНИЕ/new/.rss")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("X (Twitter): поисковые запросы") {
                HStack {
                    TextField("например: CVE-2026 exploit", text: $newXQuery)
                    Button("Добавить") {
                        let trimmed = newXQuery.trimmingCharacters(in: .whitespaces)
                        guard !trimmed.isEmpty else { return }
                        settings.xSearchQueries.append(trimmed)
                        newXQuery = ""
                    }
                }
                ForEach(settings.xSearchQueries, id: \.self) { query in
                    HStack {
                        Text(query)
                        Spacer()
                        Button(role: .destructive) {
                            settings.xSearchQueries.removeAll { $0 == query }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }
                TextField("Nitter base URL (если нет токена X API)", text: $settings.nitterBaseURL)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Watchlist

    private var watchlistTab: some View {
        Form {
            Section {
                Toggle("Показывать и уведомлять только по watchlist", isOn: $settings.watchlistOnly)
                Text("Подписки объединяются по ИЛИ: CVE попадает в watchlist, если подходит под любую включённую. Совпадение ищется в названии, описании, CPE-данных NVD (вендор/продукт) и CWE.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Каталог") {
                LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)], spacing: 8) {
                    ForEach($settings.watchlist) { $entry in
                        if entry.isCatalog {
                            Toggle(entry.value, isOn: $entry.enabled)
                                .toggleStyle(.checkbox)
                        }
                    }
                }
            }

            Section("Свои подписки") {
                ForEach($settings.watchlist) { $entry in
                    if !entry.isCatalog {
                        HStack {
                            Toggle("", isOn: $entry.enabled).labelsHidden()
                            Text(entry.kind.title).font(.caption).foregroundStyle(.secondary)
                            Text(entry.label).bold()
                            Spacer()
                            if entry.kind != .cvss {
                                Stepper("CVSS ≥ \(String(format: "%.1f", entry.minCVSS))", value: $entry.minCVSS, in: 0...10, step: 0.5)
                                    .font(.caption)
                            }
                            Button(role: .destructive) {
                                settings.watchlist.removeAll { $0.id == entry.id }
                            } label: {
                                Image(systemName: "trash")
                            }
                        }
                    }
                }

                HStack {
                    Picker("", selection: $newWatchKind) {
                        ForEach(WatchKind.allCases) { kind in
                            Text(kind.title).tag(kind)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 130)

                    TextField(placeholder(for: newWatchKind), text: $newWatchValue)

                    if newWatchKind != .cvss {
                        Stepper("≥ \(String(format: "%.1f", newWatchMinCVSS))", value: $newWatchMinCVSS, in: 0...10, step: 0.5)
                            .font(.caption)
                    }

                    Button("Добавить") {
                        let trimmed = newWatchValue.trimmingCharacters(in: .whitespaces)
                        guard !trimmed.isEmpty else { return }
                        settings.watchlist.append(WatchEntry(kind: newWatchKind, value: trimmed, minCVSS: newWatchKind == .cvss ? 0 : newWatchMinCVSS))
                        newWatchValue = ""
                        newWatchMinCVSS = 0
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onChange(of: settings.watchlist) { _, _ in
            refreshDerived()
        }
        .onChange(of: settings.watchlistOnly) { _, _ in
            refreshDerived()
        }
    }

    private func placeholder(for kind: WatchKind) -> String {
        switch kind {
        case .vendor: return "например: Fortinet"
        case .product: return "например: Tomcat"
        case .technology: return "например: Log4j"
        case .cwe: return "например: CWE-79 или 79"
        case .cvss: return "например: 9.0"
        }
    }

    // MARK: - Достоверность

    private var reliabilityTab: some View {
        Form {
            Section("Коэффициенты источников") {
                ForEach(SourceKind.allCases) { kind in
                    HStack {
                        Image(systemName: kind.icon).frame(width: 20)
                        Text(kind.displayName).frame(width: 130, alignment: .leading)
                        Slider(
                            value: Binding(
                                get: { settings.weight(for: kind) },
                                set: { settings.sourceWeights[kind.rawValue] = $0 }
                            ),
                            in: 0...1,
                            step: 0.05,
                            onEditingChanged: { editing in
                                if !editing { refreshDerived() }
                            }
                        )
                        Text(String(format: "%.2f", settings.weight(for: kind)))
                            .font(.caption.monospacedDigit())
                            .frame(width: 36)
                    }
                }
                Button("Сбросить к значениям по умолчанию") {
                    settings.sourceWeights = [:]
                    refreshDerived()
                }
                Text("Source confidence = 1 − ∏(1 − вес типа источника), где для каждого типа учитываются до 3 упоминаний. Подтверждение от нескольких независимых типов быстро повышает оценку.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Порог уверенности PoC") {
                HStack {
                    Slider(
                        value: Binding(
                            get: { Double(settings.minPoCConfidence) },
                            set: { settings.minPoCConfidence = Int($0) }
                        ),
                        in: 0...100,
                        step: 5,
                        onEditingChanged: { editing in
                            if !editing { refreshDerived() }
                        }
                    )
                    Text("\(settings.minPoCConfidence)%")
                        .font(.caption.monospacedDigit())
                        .frame(width: 40)
                }
                Text("Репозитории ниже порога сохраняются, но не считаются PoC (не попадают в Exploitable, уведомления и подсчёт времени до PoC).")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Уведомления

    private var notificationsTab: some View {
        Form {
            Section("Типы уведомлений") {
                Toggle("🔴 Новая уязвимость (CVSS не ниже порога)", isOn: $settings.notifyNewVuln)
                Toggle("⚠️ Обнаружен PoC", isOn: $settings.notifyPoC)
                Toggle("🚨 Обнаружен эксплойт (Exploit-DB / Metasploit / GitHub)", isOn: $settings.notifyExploit)
                Toggle("🔥 CVE добавлена в CISA KEV", isOn: $settings.notifyKEV)
                Toggle("📈 Trending (рост упоминаний ≥ 300%)", isOn: $settings.notifyTrending)
            }

            Section("Фильтры") {
                VStack(alignment: .leading) {
                    Text("Минимальный CVSS для «новой уязвимости»: \(String(format: "%.1f", settings.minCVSSForNotification))")
                    Slider(value: $settings.minCVSSForNotification, in: 0...10, step: 0.5)
                }
                VStack(alignment: .leading) {
                    Text("Минимальная достоверность источников: \(Int(settings.minSourceConfidenceForNotification * 100))%")
                    Slider(value: $settings.minSourceConfidenceForNotification, in: 0...1, step: 0.05)
                }
                Toggle("Только по watchlist", isOn: $settings.watchlistOnly)
                Text("На одну CVE приходит одно уведомление за цикл: если одновременно появились KEV и PoC, заголовок берётся по приоритету (KEV → Exploit → PoC → New → Trending), остальное указывается в тексте. Не больше 6 баннеров за цикл. Первый запуск после установки или обновления «молчаливый»: текущее состояние запоминается без уведомлений.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Токены

    private var tokensTab: some View {
        Form {
            if !savedMessage.isEmpty {
                Text(savedMessage).font(.caption).foregroundStyle(.green)
            }

            Section("GitHub Personal Access Token") {
                SecureField("ghp_… или github_pat_…", text: $githubToken)
                HStack {
                    Button("Сохранить") {
                        settings.githubToken = githubToken
                        Task { await GitHubRateLimiter.shared.reset() }
                        savedMessage = "GitHub-токен сохранён в Keychain"
                    }
                    Text(settings.githubToken.isEmpty ? "не задан" : "задан ✓")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Link("Создать токен", destination: URL(string: "https://github.com/settings/tokens")!)
                }
                Text("Права не нужны: подойдёт classic-токен без галочек или fine-grained с доступом «Public repositories (read-only)». Токен поднимает лимиты (поиск 10 → 30 запросов/мин) и включает поиск Nuclei-шаблонов и анализ файлов репозиториев.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("NVD API Key (необязательно)") {
                SecureField("Повышает лимит с 5 до 50 запросов / 30 сек", text: $nvdAPIKey)
                HStack {
                    Button("Сохранить") {
                        settings.nvdAPIKey = nvdAPIKey
                        savedMessage = "NVD-ключ сохранён в Keychain"
                    }
                    Text(settings.nvdAPIKey.isEmpty ? "не задан" : "задан ✓")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Link("Получить ключ", destination: URL(string: "https://nvd.nist.gov/developers/request-an-api-key")!)
                }
            }

            Section("X (Twitter) Bearer Token") {
                SecureField("Требует платный доступ к X API v2", text: $xBearerToken)
                HStack {
                    Button("Сохранить") {
                        settings.xBearerToken = xBearerToken
                        savedMessage = "X-токен сохранён в Keychain"
                    }
                    Text(settings.xBearerToken.isEmpty ? "не задан" : "задан ✓")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Link("X Developer Portal", destination: URL(string: "https://developer.x.com/en/portal/dashboard")!)
                }
            }
        }
        .formStyle(.grouped)
    }
}
