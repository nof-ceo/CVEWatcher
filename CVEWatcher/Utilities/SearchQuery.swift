import Foundation

enum SearchQueryError: Error, LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let text): return text
        }
    }
}

enum SearchOp: String {
    case eq = "="
    case colon = ":"
    case ne = "!="
    case gt = ">"
    case ge = ">="
    case lt = "<"
    case le = "<="
}

indirect enum SearchNode {
    case and([SearchNode])
    case or([SearchNode])
    case not(SearchNode)
    case text(String)
    case field(name: String, op: SearchOp, value: String)
}

/// Локальный язык запросов: `rce AND poc AND cvss >= 8`, `vendor:apache NOT kev`, `published < 7d`.
struct SearchQuery {
    let root: SearchNode?

    static let fieldNames: Set<String> = [
        "id", "vendor", "product", "cvss", "epss", "cwe", "published", "modified",
        "poc", "exploit", "kev", "metasploit", "msf", "favorite", "fav", "trending", "watchlist", "watched",
        "sources", "confidence", "tag", "source", "title", "summary"
    ]

    // MARK: - Публичный API

    static func compile(_ text: String) -> (query: SearchQuery?, error: String?) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return (nil, nil) }
        do {
            return (try parse(trimmed), nil)
        } catch {
            return (plain(trimmed), error.localizedDescription)
        }
    }

    static func plain(_ text: String) -> SearchQuery {
        let words = text.split(whereSeparator: { $0.isWhitespace }).map { SearchNode.text(String($0)) }
        return SearchQuery(root: words.isEmpty ? nil : .and(words))
    }

    static func parse(_ input: String) throws -> SearchQuery {
        let tokens = try tokenize(input)
        if tokens.isEmpty { return SearchQuery(root: nil) }
        var parser = Parser(tokens: tokens)
        let node = try parser.parseOr()
        if parser.pos < tokens.count {
            throw SearchQueryError.message("Лишние символы в запросе (проверьте скобки)")
        }
        return SearchQuery(root: node)
    }

    func matches(_ item: CVEItem, now: Date = Date()) -> Bool {
        guard let root else { return true }
        return SearchQuery.eval(root, item, now)
    }

    // MARK: - Токенизатор

    fileprivate enum Token: Equatable {
        case lparen, rparen, and, or, not
        case word(String)
        case op(SearchOp)
    }

    private static func tokenize(_ input: String) throws -> [Token] {
        var tokens: [Token] = []
        let chars = Array(input)
        var i = 0
        var current = ""

        func flush() {
            guard !current.isEmpty else { return }
            switch current {
            case "AND": tokens.append(.and)
            case "OR": tokens.append(.or)
            case "NOT": tokens.append(.not)
            default: tokens.append(.word(current))
            }
            current = ""
        }

        while i < chars.count {
            let c = chars[i]
            if c.isWhitespace { flush(); i += 1; continue }
            if c == "(" { flush(); tokens.append(.lparen); i += 1; continue }
            if c == ")" { flush(); tokens.append(.rparen); i += 1; continue }

            if c == "\"" {
                flush()
                var phrase = ""
                i += 1
                while i < chars.count, chars[i] != "\"" {
                    phrase.append(chars[i])
                    i += 1
                }
                if i >= chars.count { throw SearchQueryError.message("Не закрыта кавычка") }
                i += 1
                tokens.append(.word(phrase))
                continue
            }

            let nextIsEq = i + 1 < chars.count && chars[i + 1] == "="
            if c == ">" || c == "<" || c == "=" || c == ":" || (c == "!" && nextIsEq) {
                flush()
                var symbol = String(c)
                if (c == ">" || c == "<" || c == "!") && nextIsEq {
                    symbol += "="
                    i += 1
                }
                i += 1
                guard let op = SearchOp(rawValue: symbol) else {
                    throw SearchQueryError.message("Неизвестный оператор \(symbol)")
                }
                tokens.append(.op(op))
                continue
            }

            current.append(c)
            i += 1
        }
        flush()
        return tokens
    }

    // MARK: - Парсер

    fileprivate struct Parser {
        let tokens: [Token]
        var pos = 0

        init(tokens: [Token]) {
            self.tokens = tokens
        }

        mutating func parseOr() throws -> SearchNode {
            var nodes = [try parseAnd()]
            while pos < tokens.count, tokens[pos] == .or {
                pos += 1
                nodes.append(try parseAnd())
            }
            return nodes.count == 1 ? nodes[0] : .or(nodes)
        }

        mutating func parseAnd() throws -> SearchNode {
            var nodes = [try parseUnary()]
            while pos < tokens.count {
                if tokens[pos] == .and {
                    pos += 1
                    nodes.append(try parseUnary())
                } else if tokens[pos] == .or || tokens[pos] == .rparen {
                    break
                } else {
                    nodes.append(try parseUnary()) // неявный AND
                }
            }
            return nodes.count == 1 ? nodes[0] : .and(nodes)
        }

        mutating func parseUnary() throws -> SearchNode {
            guard pos < tokens.count else {
                throw SearchQueryError.message("Неожиданный конец запроса")
            }
            let token = tokens[pos]
            switch token {
            case .not:
                pos += 1
                return .not(try parseUnary())
            case .lparen:
                pos += 1
                let node = try parseOr()
                guard pos < tokens.count, tokens[pos] == .rparen else {
                    throw SearchQueryError.message("Не закрыта скобка")
                }
                pos += 1
                return node
            case .word(let word):
                pos += 1
                if pos < tokens.count, case .op(let op) = tokens[pos] {
                    pos += 1
                    guard pos < tokens.count, case .word(let value) = tokens[pos] else {
                        throw SearchQueryError.message("После «\(word)\(op.rawValue)» нужно значение")
                    }
                    pos += 1
                    let name = word.lowercased()
                    guard SearchQuery.fieldNames.contains(name) else {
                        throw SearchQueryError.message("Неизвестное поле «\(word)»")
                    }
                    return .field(name: name, op: op, value: value)
                }
                return .text(word)
            case .op(let op):
                throw SearchQueryError.message("Неожиданный оператор «\(op.rawValue)»")
            case .and, .or:
                throw SearchQueryError.message("Неожиданный AND/OR")
            case .rparen:
                throw SearchQueryError.message("Лишняя закрывающая скобка")
            }
        }
    }

    // MARK: - Вычисление

    private static func eval(_ node: SearchNode, _ item: CVEItem, _ now: Date) -> Bool {
        switch node {
        case .and(let nodes):
            return nodes.allSatisfy { eval($0, item, now) }
        case .or(let nodes):
            return nodes.contains { eval($0, item, now) }
        case .not(let inner):
            return !eval(inner, item, now)
        case .text(let word):
            return matchText(word, item)
        case .field(let name, let op, let value):
            return matchField(name, op, value, item, now)
        }
    }

    private static let synonyms: [String: [String]] = [
        "rce": ["remote code execution", "arbitrary code", "command injection", "code execution"],
        "xss": ["cross site scripting"],
        "sqli": ["sql injection"],
        "lpe": ["privilege escalation", "elevation of privilege"],
        "privesc": ["privilege escalation", "elevation of privilege"],
        "dos": ["denial of service"],
        "ssrf": ["server side request forgery"],
        "lfi": ["local file inclusion", "path traversal"]
    ]

    private static func flag(_ name: String, _ item: CVEItem) -> Bool? {
        switch name {
        case "poc": return item.hasPoC
        case "exploit": return item.hasExploit
        case "kev": return item.isKEV
        case "metasploit", "msf": return item.hasMetasploit
        case "favorite", "fav": return item.isFavorite
        case "trending": return item.isTrending
        case "watchlist", "watched": return item.isWatched
        default: return nil
        }
    }

    private static func blob(of item: CVEItem) -> String {
        item.searchBlob.isEmpty ? item.buildSearchBlob() : item.searchBlob
    }

    private static func containsWord(_ blob: String, _ rawWord: String) -> Bool {
        let trimmed = normalizeForMatch(rawWord).trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return true }
        if trimmed.count < 5 { return blob.contains(" " + trimmed + " ") }
        return blob.contains(trimmed)
    }

    private static func matchText(_ word: String, _ item: CVEItem) -> Bool {
        let lower = word.lowercased()
        if let value = flag(lower, item) { return value }
        let itemBlob = blob(of: item)
        if containsWord(itemBlob, lower) { return true }
        if let list = synonyms[lower] {
            return list.contains { itemBlob.contains(normalizeForMatch($0).trimmingCharacters(in: .whitespaces)) }
        }
        return false
    }

    private static func compare(_ lhs: Double, _ op: SearchOp, _ rhs: Double) -> Bool {
        switch op {
        case .eq: return abs(lhs - rhs) < 0.0001
        case .ne: return abs(lhs - rhs) >= 0.0001
        case .gt: return lhs > rhs
        case .ge, .colon: return lhs >= rhs
        case .lt: return lhs < rhs
        case .le: return lhs <= rhs
        }
    }

    private static func matchField(_ name: String, _ op: SearchOp, _ value: String, _ item: CVEItem, _ now: Date) -> Bool {
        let lowerValue = value.lowercased()

        // Булевы поля: poc:yes / exploit=false / kev:no
        if let flagValue = flag(name, item) {
            let falsy: Set<String> = ["no", "false", "0", "n", "нет"]
            let wanted = !falsy.contains(lowerValue)
            let result = flagValue == wanted
            return op == .ne ? !result : result
        }

        switch name {
        case "cvss":
            guard let score = item.cvssScore, let number = Double(value.replacingOccurrences(of: ",", with: ".")) else { return false }
            return compare(score, op, number)

        case "epss":
            guard let score = item.epssScore, var number = Double(value.replacingOccurrences(of: ",", with: ".")) else { return false }
            if number > 1 { number /= 100 }
            return compare(score, op, number)

        case "sources":
            guard let number = Double(value) else { return false }
            return compare(Double(item.mentions.count), op, number)

        case "confidence":
            guard let number = Double(value) else { return false }
            return compare(item.sourceConfidence * 100, op, number)

        case "published":
            return compareDate(item.publishedDate, op, value, now)

        case "modified":
            return compareDate(item.lastModifiedDate, op, value, now)

        case "id":
            return textResult(item.cveID.lowercased().contains(lowerValue), op)

        case "title":
            return textResult(item.title.lowercased().contains(lowerValue), op)

        case "summary":
            return textResult(item.summary.lowercased().contains(lowerValue), op)

        case "vendor":
            let hit = (item.vendor ?? "").lowercased().contains(lowerValue)
                || item.cpePairs.contains { $0.vendor.contains(lowerValue) }
            return textResult(hit, op)

        case "product":
            let hit = (item.product ?? "").lowercased().contains(lowerValue)
                || item.cpePairs.contains { $0.product.contains(lowerValue) }
            return textResult(hit, op)

        case "cwe":
            let digits = value.filter { $0.isNumber }
            let hit = !digits.isEmpty && item.cwes.contains("CWE-\(digits)")
            return textResult(hit, op)

        case "tag":
            let hit = item.tags.contains { $0.lowercased() == lowerValue } || item.tags.contains { $0.lowercased().contains(lowerValue) }
            return textResult(hit, op)

        case "source":
            let hit = item.mentions.contains {
                $0.kind.rawValue.lowercased() == lowerValue || $0.kind.displayName.lowercased().contains(lowerValue)
            }
            return textResult(hit, op)

        default:
            return false
        }
    }

    private static func textResult(_ hit: Bool, _ op: SearchOp) -> Bool {
        op == .ne ? !hit : hit
    }

    private static func compareDate(_ date: Date?, _ op: SearchOp, _ value: String, _ now: Date) -> Bool {
        guard let date else { return false }
        let trimmed = value.trimmingCharacters(in: CharacterSet(charactersIn: "-")).lowercased()

        // Относительное значение: 24h, 7d, 2w, 1m
        if let unit = trimmed.last, "hdwm".contains(unit), let amount = Double(trimmed.dropLast()) {
            let multipliers: [Character: Double] = ["h": 3600, "d": 86400, "w": 604800, "m": 2592000]
            let seconds = amount * (multipliers[unit] ?? 86400)
            let age = now.timeIntervalSince(date)
            switch op {
            case .colon, .le, .lt: return age <= seconds        // "новее, чем"
            case .gt, .ge: return age >= seconds                // "старше, чем"
            case .eq: return abs(age - seconds) < 3600
            case .ne: return abs(age - seconds) >= 3600
            }
        }

        // Абсолютная дата: 2026-01-31 или 2026-01
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        var target: Date?
        for format in ["yyyy-MM-dd", "yyyy-MM"] {
            formatter.dateFormat = format
            if let parsed = formatter.date(from: trimmed) { target = parsed; break }
        }
        guard let target else { return false }

        let calendar = Calendar.current
        switch op {
        case .colon, .eq: return calendar.isDate(date, inSameDayAs: target)
        case .ne: return !calendar.isDate(date, inSameDayAs: target)
        case .gt: return date > target
        case .ge: return date >= target
        case .lt: return date < target
        case .le: return date <= target
        }
    }
}
