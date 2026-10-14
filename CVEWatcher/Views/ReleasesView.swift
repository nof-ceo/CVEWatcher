import SwiftUI
import SwiftData

struct ReleasesView: View {
    @Query(sort: \ReleaseItem.discoveredAt, order: .reverse) private var releases: [ReleaseItem]

    var body: some View {
        List(releases) { release in
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(release.repo).font(.headline)
                    Text(release.tag)
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.blue.opacity(0.15))
                        .clipShape(Capsule())
                    if release.mentionsSecurity {
                        Label("security", systemImage: "lock.shield")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    Spacer()
                    if let date = release.publishedAt {
                        Text(date.relativeDescription).font(.caption).foregroundStyle(.secondary)
                    }
                }
                if release.name != release.tag {
                    Text(release.name).font(.subheadline).foregroundStyle(.secondary)
                }
                if !release.cveIDs.isEmpty {
                    Text(release.cveIDs.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                if let url = URL(string: release.url) {
                    Link("Открыть релиз", destination: url).font(.caption)
                }
            }
            .padding(.vertical, 4)
        }
        .overlay {
            if releases.isEmpty {
                ContentUnavailableView(
                    "Релизов пока нет",
                    systemImage: "shippingbox",
                    description: Text("Репозитории для отслеживания настраиваются в Настройки → Источники.")
                )
            }
        }
        .navigationSubtitle("\(releases.count) релизов")
    }
}
