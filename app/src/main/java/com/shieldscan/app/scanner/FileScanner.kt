package com.shieldscan.app.scanner

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import com.shieldscan.app.data.model.FileFinding
import com.shieldscan.app.data.model.ScanSummary
import com.shieldscan.app.data.model.ScanType
import com.shieldscan.app.data.signature.SignatureRepository
import com.shieldscan.app.util.HashUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Recursively scans a user-picked folder (chosen via Storage Access Framework, so no broad
 * storage permission is required) hashing each file for a signature-database match and applying
 * [HeuristicsEngine] to its name, extension, and content entropy.
 */
class FileScanner(
    private val context: Context,
    private val signatureRepository: SignatureRepository
) {
    suspend fun scanTree(
        treeUri: Uri,
        onProgress: (scanned: Int, label: String) -> Unit = { _, _ -> }
    ): ScanSummary = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val root = DocumentFile.fromTreeUri(context, treeUri)
        if (root == null || !root.exists()) {
            return@withContext ScanSummary(ScanType.FILES, startedAt, System.currentTimeMillis(), 0, emptyList())
        }

        val findings = mutableListOf<FileFinding>()
        var scannedCount = 0
        val queue = ArrayDeque<DocumentFile>()
        queue.add(root)

        while (queue.isNotEmpty() && scannedCount < MAX_FILES) {
            val current = queue.removeFirst()
            val children = runCatching { current.listFiles() }.getOrDefault(emptyArray())
            for (child in children) {
                if (scannedCount >= MAX_FILES) break
                if (child.isDirectory) {
                    queue.add(child)
                    continue
                }
                if (!child.isFile) continue

                scannedCount++
                val name = child.name ?: "unknown"
                onProgress(scannedCount, name)
                scanSingleFile(child, name)?.let { findings += it }
            }
        }

        ScanSummary(
            scanType = ScanType.FILES,
            startedAtEpochMs = startedAt,
            finishedAtEpochMs = System.currentTimeMillis(),
            itemsScanned = scannedCount,
            findings = findings.sortedByDescending { it.riskScore }
        )
    }

    private fun scanSingleFile(doc: DocumentFile, name: String): FileFinding? {
        val size = doc.length()
        if (size <= 0) return null

        if (size > MAX_HASHABLE_BYTES) {
            val heuristic = HeuristicsEngine.scoreFile(name, entropy = 0.0, sizeBytes = size)
            if (heuristic.score == 0) return null
            val reasons = heuristic.reasons + "File exceeds ${MAX_HASHABLE_BYTES / (1024 * 1024)}MB — skipped content hashing/entropy scan"
            return FileFinding(
                fileName = name,
                filePath = doc.uri.toString(),
                sizeBytes = size,
                entropy = 0.0,
                sha256 = "",
                riskScore = heuristic.score,
                reasons = reasons
            )
        }

        val digestResult = runCatching {
            context.contentResolver.openInputStream(doc.uri)?.use { HashUtils.digest(it) }
        }.getOrNull() ?: return null

        val matchedSignature = signatureRepository.lookup(digestResult.sha256)
        val heuristic = HeuristicsEngine.scoreFile(name, digestResult.entropy, digestResult.sizeBytes)

        var score = heuristic.score
        val reasons = heuristic.reasons.toMutableList()
        val signature = matchedSignature
        if (signature != null) {
            score = 100
            reasons.add(0, "Matches known-malware signature: ${signature.name}")
        }

        if (score == 0 && signature == null) return null

        return FileFinding(
            fileName = name,
            filePath = doc.uri.toString(),
            sizeBytes = digestResult.sizeBytes,
            entropy = digestResult.entropy,
            sha256 = digestResult.sha256,
            riskScore = score,
            reasons = reasons,
            matchedSignature = signature
        )
    }

    private companion object {
        const val MAX_FILES = 5000
        const val MAX_HASHABLE_BYTES = 150L * 1024 * 1024
    }
}
