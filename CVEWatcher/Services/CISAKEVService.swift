import Foundation

/// Каталог известных эксплуатируемых уязвимостей от CISA.
/// https://www.cisa.gov/known-exploited-vulnerabilities-catalog
struct CISAKEVService {

    struct Catalog: Decodable {
        let vulnerabilities: [Entry]
    }

    struct Entry: Decodable {
        let cveID: String
        let vendorProject: String?
        let product: String?
        let vulnerabilityName: String?
        let shortDescription: String?
        let dateAdded: String?
        let dueDate: String?
        let requiredAction: String?
        let knownRansomwareCampaignUse: String?

        enum CodingKeys: String, CodingKey {
            case cveID
            case vendorProject
            case product
            case vulnerabilityName
            case shortDescription
            case dateAdded
            case dueDate
            case requiredAction
            case knownRansomwareCampaignUse
        }
    }

    static let feedURL = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!

    static func fetchCatalog() async throws -> [Entry] {
        let catalog = try await NetworkClient.fetchJSON(url: feedURL, as: Catalog.self)
        return catalog.vulnerabilities
    }

    /// Возвращает только записи, добавленные в каталог за последние `days` дней —
    /// это самый близкий к "новым" срез, так как KEV не публикует даты первого раскрытия отдельно.
    static func fetchRecentlyAdded(days: Int = 3) async throws -> [Entry] {
        let all = try await fetchCatalog()
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let cutoff = Calendar.current.date(byAdding: .day, value: -days, to: .now) ?? .distantPast

        return all.filter { entry in
            guard let dateString = entry.dateAdded, let date = formatter.date(from: dateString) else { return false }
            return date >= cutoff
        }
    }
}
