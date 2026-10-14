import Foundation

/// Мониторинг X (Twitter) на предмет упоминаний CVE/эксплойтов.
///
/// ВАЖНО об ограничениях:
/// 1) Официальный X API v2 (recent search) требует платный доступ (минимум уровень Basic,
///    ~$100+/мес) и bearer-токен. Если токен задан в настройках — используется он.
/// 2) Без токена используется фолбэк через настраиваемый Nitter-инстанс (RSS-подобный
///    веб-фронтенд для X). Публичные инстансы Nitter нестабильны и часто недоступны —
///    рекомендуется поднять свой или использовать адрес, который пользователь укажет
///    в настройках (nitterBaseURL). Если адрес не задан — источник просто пропускается.
struct XMonitorService {

    struct SearchResponse: Decodable {
        let data: [Tweet]?
    }
    struct Tweet: Decodable {
        let id: String
        let text: String
        let created_at: String?
        let author_id: String?
    }

    static func fetchMentions(queries: [String], bearerToken: String?, nitterBaseURL: String?) async -> [RSSMention] {
        if let bearerToken, !bearerToken.isEmpty {
            return await fetchViaOfficialAPI(queries: queries, bearerToken: bearerToken)
        } else if let nitterBaseURL, !nitterBaseURL.isEmpty {
            return await fetchViaNitter(queries: queries, baseURL: nitterBaseURL)
        } else {
            return []
        }
    }

    // MARK: - Официальный API v2

    private static func fetchViaOfficialAPI(queries: [String], bearerToken: String) async -> [RSSMention] {
        var mentions: [RSSMention] = []
        let isoFormatter = ISO8601DateFormatter()

        for query in queries {
            var components = URLComponents(string: "https://api.twitter.com/2/tweets/search/recent")!
            components.queryItems = [
                URLQueryItem(name: "query", value: "\(query) -is:retweet lang:en"),
                URLQueryItem(name: "max_results", value: "25"),
                URLQueryItem(name: "tweet.fields", value: "created_at")
            ]
            guard let url = components.url else { continue }

            do {
                let response = try await NetworkClient.fetchJSON(
                    url: url,
                    headers: ["Authorization": "Bearer \(bearerToken)"],
                    as: SearchResponse.self
                )
                for tweet in response.data ?? [] {
                    let cveIDs = CVERegex.findAll(in: tweet.text)
                    guard !cveIDs.isEmpty else { continue }
                    mentions.append(RSSMention(
                        cveIDs: cveIDs,
                        articleTitle: "Пост в X",
                        articleURL: "https://twitter.com/i/web/status/\(tweet.id)",
                        articleSummary: tweet.text,
                        publishedDate: tweet.created_at.flatMap { isoFormatter.date(from: $0) },
                        kind: .x
                    ))
                }
            } catch {
                print("X API ошибка для запроса '\(query)': \(error)")
            }
        }
        return mentions
    }

    // MARK: - Фолбэк через Nitter (RSS-лента поиска)

    private static func fetchViaNitter(queries: [String], baseURL: String) async -> [RSSMention] {
        var mentions: [RSSMention] = []
        let trimmedBase = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        for query in queries {
            guard let encoded = query.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
                  let url = URL(string: "\(trimmedBase)/search/rss?f=tweets&q=\(encoded)") else { continue }

            do {
                let data = try await NetworkClient.fetchRawData(url: url)
                let articles = RSSParser.parse(data: data)
                for article in articles {
                    let cveIDs = CVERegex.findAll(in: article.title + " " + article.summary)
                    guard !cveIDs.isEmpty else { continue }
                    mentions.append(RSSMention(
                        cveIDs: cveIDs,
                        articleTitle: "Пост в X (через Nitter)",
                        articleURL: article.link,
                        articleSummary: article.summary,
                        publishedDate: article.publishedDate,
                        kind: .x
                    ))
                }
            } catch {
                print("Nitter ошибка для запроса '\(query)': \(error)")
            }
        }
        return mentions
    }
}
