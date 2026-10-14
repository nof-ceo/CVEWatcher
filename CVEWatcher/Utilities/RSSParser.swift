import Foundation

struct RSSArticle: Sendable {
    let title: String
    let link: String
    let summary: String
    let publishedDate: Date?
}

/// Простой парсер RSS 2.0 и Atom без внешних зависимостей.
final class RSSParser: NSObject, XMLParserDelegate {

    private var articles: [RSSArticle] = []

    private var currentElement = ""
    private var currentTitle = ""
    private var currentLink = ""
    private var currentSummary = ""
    private var currentDateString = ""
    private var insideItem = false
    private var linkFromAttribute = false

    static func parse(data: Data) -> [RSSArticle] {
        let handler = RSSParser()
        let xmlParser = XMLParser(data: data)
        xmlParser.delegate = handler
        xmlParser.parse()
        return handler.articles
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        currentElement = elementName

        if elementName == "item" || elementName == "entry" {
            insideItem = true
            currentTitle = ""
            currentLink = ""
            currentSummary = ""
            currentDateString = ""
            linkFromAttribute = false
        }

        // Atom: <link rel="alternate" href="..."/>
        if insideItem, elementName == "link", let href = attributeDict["href"], !href.isEmpty {
            let rel = attributeDict["rel"] ?? "alternate"
            if rel == "alternate" || currentLink.isEmpty {
                currentLink = href
                linkFromAttribute = true
            }
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        appendText(string)
    }

    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        if let string = String(data: CDATABlock, encoding: .utf8) {
            appendText(string)
        }
    }

    private func appendText(_ string: String) {
        guard insideItem else { return }
        switch currentElement {
        case "title":
            currentTitle += string
        case "link":
            // Для Atom текст внутри <link> пустой, href уже взят из атрибута.
            if !linkFromAttribute {
                currentLink += string
            }
        case "description", "summary", "content", "content:encoded":
            currentSummary += string
        case "pubDate", "published", "updated", "dc:date":
            currentDateString += string
        default:
            break
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if elementName == "item" || elementName == "entry" {
            let article = RSSArticle(
                title: currentTitle.trimmingCharacters(in: .whitespacesAndNewlines),
                link: currentLink.trimmingCharacters(in: .whitespacesAndNewlines),
                summary: stripHTML(currentSummary).trimmingCharacters(in: .whitespacesAndNewlines),
                publishedDate: parseDate(currentDateString.trimmingCharacters(in: .whitespacesAndNewlines))
            )
            articles.append(article)
            insideItem = false
        }
        currentElement = ""
    }

    private func parseDate(_ string: String) -> Date? {
        guard !string.isEmpty else { return nil }

        let iso = ISO8601DateFormatter()
        if let date = iso.date(from: string) { return date }

        let isoFraction = ISO8601DateFormatter()
        isoFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = isoFraction.date(from: string) { return date }

        let rfc822 = DateFormatter()
        rfc822.locale = Locale(identifier: "en_US_POSIX")
        for format in ["EEE, dd MMM yyyy HH:mm:ss Z", "EEE, dd MMM yyyy HH:mm:ss zzz", "dd MMM yyyy HH:mm:ss Z"] {
            rfc822.dateFormat = format
            if let date = rfc822.date(from: string) { return date }
        }
        return nil
    }

    private func stripHTML(_ string: String) -> String {
        string.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
    }
}
