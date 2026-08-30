package com.sentinelscan.app

import android.content.Context
import org.json.JSONObject

data class SignatureHit(
    val id: String,
    val name: String,
    val severity: String,
    val description: String,
)

/**
 * Local threat-signature database, mirroring data/signatures.json from the
 * sentinel-scan CLI: exact-hash matches plus regex content patterns.
 */
class SignatureDatabase private constructor(
    val version: String,
    private val hashesBySha256: Map<String, SignatureHit>,
    private val hashesByMd5: Map<String, SignatureHit>,
    private val patterns: List<Pair<SignatureHit, Regex>>,
) {
    val hashCount: Int get() = hashesBySha256.size
    val patternCount: Int get() = patterns.size

    fun matchHash(sha256: String, md5: String): SignatureHit? =
        hashesBySha256[sha256.lowercase()] ?: hashesByMd5[md5.lowercase()]

    fun matchPatterns(content: String): List<SignatureHit> =
        patterns.filter { (_, regex) -> regex.containsMatchIn(content) }.map { it.first }

    companion object {
        fun load(context: Context, assetName: String = "signatures.json"): SignatureDatabase {
            val json = context.assets.open(assetName).bufferedReader().use { it.readText() }
            val root = JSONObject(json)
            val version = root.optString("version", "0")

            val hashesBySha256 = mutableMapOf<String, SignatureHit>()
            val hashesByMd5 = mutableMapOf<String, SignatureHit>()
            val hashesArray = root.getJSONArray("hashes")
            for (i in 0 until hashesArray.length()) {
                val entry = hashesArray.getJSONObject(i)
                val hit = SignatureHit(
                    id = entry.getString("id"),
                    name = entry.getString("name"),
                    severity = entry.getString("severity"),
                    description = entry.getString("description"),
                )
                if (entry.has("sha256")) hashesBySha256[entry.getString("sha256").lowercase()] = hit
                if (entry.has("md5")) hashesByMd5[entry.getString("md5").lowercase()] = hit
            }

            val patterns = mutableListOf<Pair<SignatureHit, Regex>>()
            val patternsArray = root.getJSONArray("patterns")
            for (i in 0 until patternsArray.length()) {
                val entry = patternsArray.getJSONObject(i)
                val hit = SignatureHit(
                    id = entry.getString("id"),
                    name = entry.getString("name"),
                    severity = entry.getString("severity"),
                    description = entry.getString("description"),
                )
                val flags = entry.optString("flags", "")
                val options = mutableSetOf<RegexOption>()
                if (flags.contains("i")) options.add(RegexOption.IGNORE_CASE)
                val regex = Regex(entry.getString("regex"), options)
                patterns.add(hit to regex)
            }

            return SignatureDatabase(version, hashesBySha256, hashesByMd5, patterns)
        }
    }
}
