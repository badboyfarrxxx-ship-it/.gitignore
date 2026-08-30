package com.shieldscan.app.util

import java.io.InputStream
import java.security.MessageDigest
import kotlin.math.ln

object HashUtils {

    data class DigestResult(val sha256: String, val sizeBytes: Long, val entropy: Double)

    /**
     * Single pass over [inputStream] that computes the SHA-256 hex digest and the Shannon
     * entropy (bits per byte, 0..8) of the whole stream. High entropy (roughly >7.5) suggests
     * the content is compressed, encrypted, or packed — a common trait of obfuscated malware.
     */
    fun digest(inputStream: InputStream): DigestResult {
        val md = MessageDigest.getInstance("SHA-256")
        val freq = LongArray(256)
        var total = 0L
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)

        inputStream.use { stream ->
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                md.update(buffer, 0, read)
                for (i in 0 until read) {
                    val b = buffer[i].toInt() and 0xFF
                    freq[b] = freq[b] + 1
                }
                total += read
            }
        }

        val hex = md.digest().joinToString(separator = "") { "%02x".format(it) }
        return DigestResult(sha256 = hex, sizeBytes = total, entropy = shannonEntropy(freq, total))
    }

    private fun shannonEntropy(freq: LongArray, total: Long): Double {
        if (total == 0L) return 0.0
        var entropy = 0.0
        for (count in freq) {
            if (count == 0L) continue
            val p = count.toDouble() / total
            entropy -= p * (ln(p) / ln(2.0))
        }
        return entropy
    }

    private const val DEFAULT_BUFFER_SIZE = 16 * 1024
}
