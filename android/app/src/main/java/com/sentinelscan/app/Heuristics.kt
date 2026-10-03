package com.sentinelscan.app

import kotlin.math.ln

/**
 * Non-signature heuristic checks, ported from the sentinel-scan CLI:
 * double-extension masquerade, content/extension mismatch via magic bytes,
 * macro-enabled documents, and Shannon entropy on executable-ish files.
 */
object Heuristics {
    private val EXECUTABLE_EXTENSIONS = setOf(
        "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "hta", "ps1", "psm1", "jar", "msi", "dll", "sh",
    )
    private val MACRO_EXTENSIONS = setOf("docm", "xlsm", "pptm", "dotm", "xltm")
    private val NON_EXECUTABLE_CATEGORY_EXTENSIONS = setOf(
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg",
        "png", "gif", "bmp", "txt", "csv", "rtf", "mp3", "mp4", "avi",
    )
    private val EXECUTABLE_MAGIC_TYPES = setOf("pe-executable", "elf-executable", "shell-script")
    private val DOUBLE_EXTENSION_REGEX = Regex("""\.([a-z0-9]{2,5})\.([a-z0-9]{2,5})$""")

    fun computeEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val freq = IntArray(256)
        for (b in bytes) freq[b.toInt() and 0xFF]++
        val len = bytes.size.toDouble()
        var entropy = 0.0
        for (count in freq) {
            if (count == 0) continue
            val p = count / len
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy
    }

    fun detectMagicType(bytes: ByteArray): String {
        if (bytes.size < 4) return "unknown"
        val b0 = bytes[0].toInt() and 0xFF
        val b1 = bytes[1].toInt() and 0xFF
        val b2 = bytes[2].toInt() and 0xFF
        val b3 = bytes[3].toInt() and 0xFF
        return when {
            b0 == 0x4D && b1 == 0x5A -> "pe-executable"
            b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46 -> "elf-executable"
            b0 == 0x23 && b1 == 0x21 -> "shell-script"
            b0 == 0x50 && b1 == 0x4B && (b2 == 0x03 || b2 == 0x05 || b2 == 0x07) -> "zip-archive"
            b0 == 0x25 && b1 == 0x50 && b2 == 0x44 && b3 == 0x46 -> "pdf"
            b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF -> "jpeg"
            b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47 -> "png"
            b0 == 0x47 && b1 == 0x49 && b2 == 0x46 -> "gif"
            else -> "unknown"
        }
    }

    fun run(fileName: String, bytes: ByteArray): List<Detection> {
        val findings = mutableListOf<Detection>()
        val ext = fileName.substringAfterLast('.', "").lowercase()
        val lowerName = fileName.lowercase()

        val doubleExtMatch = DOUBLE_EXTENSION_REGEX.find(lowerName)
        if (doubleExtMatch != null) {
            val (first, second) = doubleExtMatch.destructured
            if (NON_EXECUTABLE_CATEGORY_EXTENSIONS.contains(first) && EXECUTABLE_EXTENSIONS.contains(second)) {
                findings.add(
                    Detection(
                        id = "HEUR-DOUBLE-EXTENSION",
                        name = "Double-Extension Masquerade",
                        severity = "high",
                        description = "Filename disguises an executable (.$second) behind a document/media extension (.$first).",
                        source = "heuristic",
                    )
                )
            }
        }

        val magicType = detectMagicType(bytes)
        if (EXECUTABLE_MAGIC_TYPES.contains(magicType) && NON_EXECUTABLE_CATEGORY_EXTENSIONS.contains(ext)) {
            findings.add(
                Detection(
                    id = "HEUR-CONTENT-EXT-MISMATCH",
                    name = "Content/Extension Mismatch",
                    severity = "high",
                    description = "File content looks like $magicType but has a \".$ext\" extension — likely a disguised executable.",
                    source = "heuristic",
                )
            )
        }

        if (MACRO_EXTENSIONS.contains(ext)) {
            findings.add(
                Detection(
                    id = "HEUR-MACRO-DOCUMENT",
                    name = "Macro-Enabled Document",
                    severity = "medium",
                    description = "Office document with macros enabled — verify the source before allowing macros to run.",
                    source = "heuristic",
                )
            )
        }

        if (EXECUTABLE_EXTENSIONS.contains(ext) || ext.isEmpty()) {
            val entropy = computeEntropy(bytes)
            if (entropy >= 7.2 && bytes.size >= 256) {
                findings.add(
                    Detection(
                        id = "HEUR-HIGH-ENTROPY",
                        name = "High Entropy Content",
                        severity = "low",
                        description = "Entropy %.2f bits/byte suggests packed, encrypted, or obfuscated content.".format(entropy),
                        source = "heuristic",
                    )
                )
            }
        }

        return findings
    }
}
