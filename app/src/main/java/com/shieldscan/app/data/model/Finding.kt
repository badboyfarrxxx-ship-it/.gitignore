package com.shieldscan.app.data.model

enum class ScanType { INSTALLED_APPS, FILES }

/** Common shape shared by [AppFinding] and [FileFinding] so the UI can render both uniformly. */
sealed interface Finding {
    val id: String
    val displayName: String
    val subtitle: String
    val sha256: String
    val riskLevel: RiskLevel
    val riskScore: Int
    val reasons: List<String>
    val matchedSignature: ThreatSignature?
}

data class AppFinding(
    val packageName: String,
    val appLabel: String,
    val versionName: String?,
    val apkSourcePath: String,
    val isSystemApp: Boolean,
    val installerPackage: String?,
    val dangerousPermissions: List<String>,
    override val sha256: String,
    override val riskScore: Int,
    override val reasons: List<String>,
    override val matchedSignature: ThreatSignature? = null
) : Finding {
    override val id: String get() = packageName
    override val displayName: String get() = appLabel
    override val subtitle: String get() = packageName
    override val riskLevel: RiskLevel get() = RiskLevel.fromScore(riskScore)
}

data class FileFinding(
    val fileName: String,
    val filePath: String,
    val sizeBytes: Long,
    val entropy: Double,
    override val sha256: String,
    override val riskScore: Int,
    override val reasons: List<String>,
    override val matchedSignature: ThreatSignature? = null
) : Finding {
    override val id: String get() = filePath
    override val displayName: String get() = fileName
    override val subtitle: String get() = filePath
    override val riskLevel: RiskLevel get() = RiskLevel.fromScore(riskScore)
}

data class ScanSummary(
    val scanType: ScanType,
    val startedAtEpochMs: Long,
    val finishedAtEpochMs: Long,
    val itemsScanned: Int,
    val findings: List<Finding>
) {
    val threatsFound: Int get() = findings.count { it.riskLevel >= RiskLevel.MEDIUM }
    val durationMs: Long get() = finishedAtEpochMs - startedAtEpochMs
}
