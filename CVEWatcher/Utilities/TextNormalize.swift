import Foundation

/// Приводит строку к виду " apache http server 2 4 ": только буквы и цифры,
/// одиночные пробелы, пробелы по краям. Позволяет искать целые слова через `contains(" слово ")`.
func normalizeForMatch(_ string: String) -> String {
    var result = " "
    var lastWasSpace = true
    for ch in string.lowercased() {
        if ch.isLetter || ch.isNumber {
            result.append(ch)
            lastWasSpace = false
        } else if !lastWasSpace {
            result.append(" ")
            lastWasSpace = true
        }
    }
    if !lastWasSpace { result.append(" ") }
    return result
}
