import Foundation

enum ItemFilter {

    static func apply(_ items: [CVEItem], filter: SidebarFilter, query: SearchQuery?, watchlistOnly: Bool) -> [CVEItem] {
        var result = items

        if watchlistOnly {
            result = result.filter { $0.isWatched }
        }

        switch filter {
        case .all, .releases:
            break
        case .watchlist:
            result = result.filter { $0.isWatched }
        case .favorites:
            result = result.filter { $0.isFavorite }
        case .kev:
            result = result.filter { $0.isKEV }
        case .exploitable:
            result = result.filter { $0.hasPoC || $0.hasExploit || $0.isKEV }
        case .trending:
            result = result.filter { $0.isTrending }.sorted { $0.trendScore > $1.trendScore }
        case .tag(let tag):
            result = result.filter { $0.tags.contains(tag) }
        }

        if let query {
            let now = Date()
            result = result.filter { query.matches($0, now: now) }
        }
        return result
    }
}
