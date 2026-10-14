import SwiftUI

struct SearchHelpView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text("Язык поиска").font(.headline)
                Text("Слова объединяются через AND (можно не писать). Поддерживаются OR, NOT и скобки.")
                    .font(.caption)

                example("rce AND poc AND cvss >= 8")
                example("vendor:apache AND NOT kev")
                example("(xss OR sqli) AND published < 7d")
                example("cwe:79 AND exploit")
                example("source:reddit AND sources >= 5")
                example("confidence >= 80 AND watchlist")

                Divider()
                Text("Поля").font(.subheadline.bold())
                Group {
                    row("id, title, summary", "текст в ID, заголовке, описании")
                    row("vendor, product", "вендор / продукт (включая CPE из NVD)")
                    row("cvss, epss", "числа; «:» означает ≥. EPSS можно в % (epss>=50)")
                    row("cwe", "cwe:79 или cwe:CWE-79")
                    row("published, modified", "даты: 2026-01-31, 2026-01 или относительные 24h, 7d, 2w, 1m")
                    row("sources, confidence", "число источников; достоверность в %")
                    row("tag, source", "тег; тип источника (reddit, x, github, vendor, exploitdb...)")
                }
                Divider()
                Text("Флаги").font(.subheadline.bold())
                Text("poc, exploit, kev, metasploit, favorite, trending, watchlist — можно писать как слово или poc:no")
                    .font(.caption)
                Divider()
                Text("Дата: «published < 7d» — опубликовано за последние 7 дней, «published > 30d» — старше 30 дней.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Короткие слова (rce, xss, sqli, dos, ssrf, lfi) понимают синонимы: remote code execution, cross-site scripting и т.д.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(14)
        }
        .frame(width: 420, height: 440)
    }

    private func example(_ text: String) -> some View {
        Text(text)
            .font(.system(.caption, design: .monospaced))
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.4))
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func row(_ name: String, _ text: String) -> some View {
        HStack(alignment: .top) {
            Text(name).font(.system(.caption, design: .monospaced)).frame(width: 130, alignment: .leading)
            Text(text).font(.caption).foregroundStyle(.secondary)
        }
    }
}
