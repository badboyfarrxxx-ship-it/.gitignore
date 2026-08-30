package com.sentinelscan.app

/** A single signature or heuristic hit against a scanned file. */
data class Detection(
    val id: String,
    val name: String,
    val severity: String,
    val description: String,
    val source: String,
)

/** How a scanned/quarantined item is addressed so it can be re-located later. */
enum class NodeType { SAF, RAW }

/** A file flagged by the scanner. `parentIdentity` + `nodeType` let quarantine restore it. */
data class Threat(
    val displayPath: String,
    val fileName: String,
    val identityKey: String,
    val nodeType: NodeType,
    val parentIdentity: String?,
    val mimeType: String?,
    val sha256: String,
    val size: Long,
    val severity: String,
    val detections: List<Detection>,
)

data class ScanReport(
    val filesScanned: Int,
    val filesSkipped: Int,
    val threats: List<Threat>,
    val durationMs: Long,
)

data class QuarantineEntry(
    val id: String,
    val originalDisplayPath: String,
    val fileName: String,
    val identityKey: String,
    val nodeType: NodeType,
    val parentIdentity: String?,
    val mimeType: String?,
    val storedFileName: String,
    val sha256: String,
    val size: Long,
    val severity: String,
    val detections: List<Detection>,
    val quarantinedAt: String,
)

object Severity {
    private val rank = mapOf("high" to 3, "medium" to 2, "low" to 1)

    fun worst(detections: List<Detection>): String =
        detections.maxByOrNull { rank[it.severity] ?: 0 }?.severity ?: "low"
}
