import SwiftUI

struct CVEDetailView: View {
    @Bindable var item: CVEItem
    @EnvironmentObject private var settings: AppSettings
    @State private var newTag: String = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header
                metricsSection
                summarySection
                chainSection
                pocSection
                sourcesSection
                historySection
                tagsSection
            }
            .padding(24)
        }
        .navigationTitle(item.cveID)
    }

    // MARK: - Заголовок

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 6) {
                Text(item.cveID).font(.largeTitle.bold())
                if !item.title.isEmpty && item.title != item.cveID {
                    Text(item.title).font(.title3).foregroundStyle(.secondary)
                }
                HStack(spacing: 10) {
                    if let vendor = item.displayVendor { Label(vendor, systemImage: "building.2") }
                    if let product = item.displayProduct { Label(product, systemImage: "shippingbox") }
                    if item.isWatched {
                        Label(item.watchLabels.joined(separator: ", "), systemImage: "eye.fill")
                            .foregroundStyle(.teal)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)

                if item.tags.contains("unconfirmed") {
                    Label("Не подтверждено авторитетным источником (NVD / CISA / vendor / GHSA)", systemImage: "questionmark.circle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            Spacer()
            Button {
                item.isFavorite.toggle()
            } label: {
                Image(systemName: item.isFavorite ? "star.fill" : "star")
                    .font(.title2)
                    .foregroundStyle(item.isFavorite ? .yellow : .secondary)
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: - Метрики

    private var metricsSection: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), alignment: .top)], alignment: .leading, spacing: 12) {
            metricCard(
                title: "CVSS",
                value: item.cvssScore.map { String(format: "%.1f", $0) } ?? "—",
                color: item.severityColor,
                subtitle: item.severityLabel
            )

            if let epss = item.epssScore {
                metricCard(title: "EPSS", value: "\(Int(epss * 100))%", color: .purple, subtitle: "вероятность эксплуатации")
            }

            metricCard(
                title: "Source confidence",
                value: "\(Int(item.sourceConfidence * 100))%",
                color: confidenceColor,
                subtitle: "по \(item.mentions.count) источникам"
            )

            if item.isKEV {
                metricCard(
                    title: "KEV",
                    value: "Да",
                    color: .red,
                    subtitle: item.kevDueDate.map { "Исправить до \(formatted($0))" } ?? "Активно эксплуатируется"
                )
            }

            if let ttp = item.timeToFirstPoC {
                metricCard(
                    title: "CVE → PoC",
                    value: (ttp < 0 ? "−" : "") + DurationFormat.string(ttp),
                    color: .blue,
                    subtitle: ttp < 0 ? "PoC раньше публикации CVE" : "до первого PoC"
                )
            }

            if item.isTrending {
                metricCard(
                    title: "Trending",
                    value: "+\(Int(item.trendScore))%",
                    color: .orange,
                    subtitle: "\(item.trendMentions1h) упоминаний за час"
                )
            }

            if let published = item.publishedDate {
                metricCard(title: "Опубликовано", value: formatted(published), color: .gray, subtitle: published.relativeDescription)
            }
        }
    }

    private var confidenceColor: Color {
        switch item.sourceConfidence {
        case 0.8...: return .green
        case 0.5..<0.8: return .yellow
        default: return .red
        }
    }

    private func metricCard(title: String, value: String, color: Color, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title.uppercased()).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.title2.bold()).foregroundStyle(color)
            Text(subtitle).font(.caption2).foregroundStyle(.secondary).lineLimit(2)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.3))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Описание

    private var summarySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Описание").font(.headline)
            Text(item.summary.isEmpty ? "Описание пока недоступно." : item.summary)
                .textSelection(.enabled)
            if let vector = item.cvssVector {
                Text("Вектор CVSS: \(vector)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    // MARK: - Цепочка CVE → PoC → Exploit

    @ViewBuilder
    private var chainSection: some View {
        let steps = item.exploitChain
        if steps.count > 1 {
            VStack(alignment: .leading, spacing: 0) {
                Text("От CVE до эксплойта").font(.headline).padding(.bottom, 8)

                ForEach(Array(steps.enumerated()), id: \.element.id) { index, step in
                    if index > 0 {
                        HStack(spacing: 8) {
                            Image(systemName: "arrow.down").font(.caption2)
                            Text(DurationFormat.string(step.date.timeIntervalSince(steps[index - 1].date)))
                                .font(.caption.monospacedDigit())
                        }
                        .foregroundStyle(.secondary)
                        .padding(.leading, 3)
                        .padding(.vertical, 4)
                    }
                    HStack(spacing: 8) {
                        Circle().fill(Color.accentColor).frame(width: 8, height: 8)
                        Text(step.label).bold()
                        if step.approximate {
                            Text("≈").foregroundStyle(.secondary).help("Дата приблизительная")
                        }
                        Spacer()
                        Text(step.date.formatted(date: .abbreviated, time: .shortened))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if let first = steps.first, first.label != "CVE опубликована", item.publishedDate != nil {
                    Text("Первый PoC/эксплойт появился раньше официальной публикации CVE.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .padding(.top, 6)
                }
            }
            .padding(12)
            .background(.quaternary.opacity(0.2))
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }

    // MARK: - PoC / Exploit

    @ViewBuilder
    private var pocSection: some View {
        if !item.pocs.isEmpty {
            let sorted = item.pocs.sorted { $0.confidence > $1.confidence }
            VStack(alignment: .leading, spacing: 8) {
                Text("PoC и эксплойты (\(item.credibleItems.count) из \(item.pocs.count) выше порога \(Thresholds.minPoCConfidence)%)")
                    .font(.headline)
                Text("Оценка — автоматическая, по названию, описанию, темам и файлам. Код не проверялся и не запускался. Запускайте только в изолированной среде.")
                    .font(.caption)
                    .foregroundStyle(.orange)

                ForEach(sorted, id: \.url) { poc in
                    let credible = poc.confidence >= Thresholds.minPoCConfidence
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(poc.isExploitGrade ? "EXPLOIT" : "PoC")
                                .font(.caption2.bold())
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background((poc.isExploitGrade ? Color.red : Color.blue).opacity(0.18))
                                .clipShape(Capsule())
                            Text(poc.sourceType.rawValue).font(.caption2).foregroundStyle(.secondary)
                            Text("\(poc.confidence)%")
                                .font(.caption.bold())
                                .foregroundStyle(credible ? Color.green : Color.secondary)
                            if let stars = poc.starCount {
                                Label("\(stars)", systemImage: "star.fill").font(.caption2)
                            }
                            Spacer()
                            Text(poc.eventDate.formatted(date: .abbreviated, time: .omitted) + (poc.isDateApproximate ? " ≈" : ""))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Link(poc.title, destination: URL(string: poc.url) ?? URL(string: "https://github.com")!)
                            .font(.callout)
                        if !poc.analysisNote.isEmpty {
                            Text(poc.analysisNote).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .padding(10)
                    .background(.quaternary.opacity(credible ? 0.25 : 0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .opacity(credible ? 1 : 0.65)
                }
            }
        }
    }

    // MARK: - Источники (дедупликация)

    @ViewBuilder
    private var sourcesSection: some View {
        let groups = Dictionary(grouping: item.mentions, by: { $0.kind })
        let kinds = groups.keys.sorted { settings.weight(for: $0) > settings.weight(for: $1) }

        VStack(alignment: .leading, spacing: 6) {
            Text("Источники: \(item.mentions.count)").font(.headline)
            if kinds.isEmpty {
                Text("Нет данных").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(kinds) { kind in
                let mentions = (groups[kind] ?? []).sorted { $0.occurredAt > $1.occurredAt }
                if mentions.count == 1, let only = mentions.first {
                    HStack(spacing: 6) {
                        Image(systemName: kind.icon).frame(width: 18)
                        if let url = URL(string: only.url) {
                            Link(kind.displayName, destination: url)
                        } else {
                            Text(kind.displayName)
                        }
                        Text(String(format: "%.2f", settings.weight(for: kind)))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(mentions, id: \.url) { mention in
                                if let url = URL(string: mention.url) {
                                    Link(mention.title.isEmpty ? mention.url : mention.title, destination: url)
                                        .font(.caption)
                                        .lineLimit(1)
                                }
                            }
                        }
                        .padding(.leading, 4)
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: kind.icon).frame(width: 18)
                            Text("\(kind.displayName) × \(mentions.count)")
                            Text(String(format: "%.2f", settings.weight(for: kind)))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    // MARK: - История изменений

    @ViewBuilder
    private var historySection: some View {
        let snapshots = item.snapshots.sorted { $0.takenAt < $1.takenAt }
        if !snapshots.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text("История изменений").font(.headline)
                ForEach(snapshots) { snapshot in
                    HStack(alignment: .top, spacing: 10) {
                        Text(snapshot.takenAt.formatted(date: .numeric, time: .shortened))
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                            .frame(width: 120, alignment: .leading)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(snapshot.summaryLine).font(.callout)
                            if !snapshot.note.isEmpty {
                                Text(snapshot.note).font(.caption).foregroundStyle(.orange)
                            }
                        }
                    }
                }
                Text("Время — момент, когда приложение заметило изменение.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Теги и CWE

    private var tagsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !item.cwes.isEmpty {
                Text("CWE").font(.headline)
                Text(item.cwes.joined(separator: ", ")).font(.callout).textSelection(.enabled)
            }
            Text("Теги").font(.headline)
            FlowLayoutTags(tags: item.tags) { tag in
                item.removeTag(tag)
            }
            HStack {
                TextField("Добавить тег", text: $newTag)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 160)
                Button("Добавить") {
                    let trimmed = newTag.trimmingCharacters(in: .whitespaces).lowercased()
                    guard !trimmed.isEmpty else { return }
                    item.addTagIfMissing(trimmed)
                    newTag = ""
                }
            }
        }
    }

    private func formatted(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        return formatter.string(from: date)
    }
}

struct FlowLayoutTags: View {
    let tags: [String]
    var onRemove: (String) -> Void

    var body: some View {
        if tags.isEmpty {
            Text("Нет тегов").font(.caption).foregroundStyle(.secondary)
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 90))], alignment: .leading, spacing: 6) {
                ForEach(tags, id: \.self) { tag in
                    HStack(spacing: 4) {
                        Text(tag).font(.caption)
                        Button {
                            onRemove(tag)
                        } label: {
                            Image(systemName: "xmark.circle.fill").font(.caption2)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(.blue.opacity(0.15))
                    .clipShape(Capsule())
                }
            }
        }
    }
}
