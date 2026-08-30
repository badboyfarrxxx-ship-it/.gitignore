package com.sentinelscan.app

import android.content.Context
import java.security.MessageDigest

/** Walks a [ScanNode] tree, applying signature + heuristic detection to every file. */
object ScanEngine {
    const val DEFAULT_MAX_FILE_BYTES = 50L * 1024 * 1024

    fun scan(
        context: Context,
        root: ScanNode,
        db: SignatureDatabase,
        maxFileBytes: Long = DEFAULT_MAX_FILE_BYTES,
        onProgress: (filesScanned: Int, currentPath: String) -> Unit = { _, _ -> },
    ): ScanReport {
        val startedAt = System.currentTimeMillis()
        var filesScanned = 0
        var filesSkipped = 0
        val threats = mutableListOf<Threat>()

        fun walk(node: ScanNode) {
            if (node.isDirectory()) {
                for (child in node.listChildren(context)) walk(child)
                return
            }

            val size = node.length()
            if (size > maxFileBytes) {
                filesSkipped += 1
                return
            }

            val bytes = try {
                node.openInputStream(context).use { it.readBytes() }
            } catch (e: Exception) {
                filesSkipped += 1
                return
            }

            filesScanned += 1
            onProgress(filesScanned, node.displayPath)

            scanBytes(node, bytes, db)?.let { threats.add(it) }
        }

        walk(root)

        return ScanReport(
            filesScanned = filesScanned,
            filesSkipped = filesSkipped,
            threats = threats,
            durationMs = System.currentTimeMillis() - startedAt,
        )
    }

    fun scanBytes(node: ScanNode, bytes: ByteArray, db: SignatureDatabase): Threat? {
        val detections = mutableListOf<Detection>()
        val sha256 = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
        val md5 = MessageDigest.getInstance("MD5").digest(bytes).toHex()

        db.matchHash(sha256, md5)?.let { hit ->
            detections.add(Detection(hit.id, hit.name, hit.severity, hit.description, "signature-hash"))
        }

        if (bytes.size <= 10 * 1024 * 1024) {
            val text = String(bytes, Charsets.ISO_8859_1)
            for (hit in db.matchPatterns(text)) {
                detections.add(Detection(hit.id, hit.name, hit.severity, hit.description, "signature-pattern"))
            }
        }

        detections.addAll(Heuristics.run(node.name, bytes))

        if (detections.isEmpty()) return null

        return Threat(
            displayPath = node.displayPath,
            fileName = node.name,
            identityKey = node.identityKey(),
            nodeType = node.nodeType,
            parentIdentity = node.parentIdentity,
            mimeType = node.mimeType,
            sha256 = sha256,
            size = bytes.size.toLong(),
            severity = Severity.worst(detections),
            detections = detections,
        )
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
