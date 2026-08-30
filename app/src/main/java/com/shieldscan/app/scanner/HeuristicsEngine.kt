package com.shieldscan.app.scanner

import com.shieldscan.app.data.signature.PermissionWeight
import java.util.Locale

/**
 * Pure, offline heuristic scoring. None of this is a substitute for real signature matching —
 * it flags *patterns* that are common in malware (dangerous permission combinations, sideloading,
 * disguised file extensions, packed/encrypted content) so a human can review, not a guaranteed verdict.
 */
object HeuristicsEngine {

    data class ScoreResult(val score: Int, val reasons: List<String>)

    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.amazon.venezia",
        "com.sec.android.app.samsungapps"
    )

    fun scoreApp(
        isSystemApp: Boolean,
        installerPackage: String?,
        requestedPermissions: List<String>,
        permissionWeightLookup: (String) -> PermissionWeight?
    ): ScoreResult {
        if (isSystemApp) {
            return ScoreResult(0, listOf("Pre-installed system app"))
        }

        val reasons = mutableListOf<String>()
        var score = 0

        val matchedWeights = requestedPermissions.mapNotNull(permissionWeightLookup)
        val permissionScore = matchedWeights.sumOf { it.weight }.coerceAtMost(70)
        if (permissionScore > 0) {
            score += permissionScore
            matchedWeights.sortedByDescending { it.weight }.take(3).forEach {
                val shortName = it.permission.substringAfterLast('.')
                reasons += "Requests $shortName — ${it.reason}"
            }
        }

        val requested = requestedPermissions.toSet()
        val hasAccessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in requested
        val hasDeviceAdmin = "android.permission.BIND_DEVICE_ADMIN" in requested
        val hasOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in requested

        if (hasAccessibility && hasOverlay) {
            score += 15
            reasons += "Combines accessibility service with screen overlays — a common banking-trojan pattern"
        }
        if (hasDeviceAdmin && (hasAccessibility || hasOverlay)) {
            score += 10
            reasons += "Combines device-admin with accessibility/overlay access — can resist uninstallation"
        }

        when {
            installerPackage == null -> {
                score += 20
                reasons += "Not installed through a known app store (sideloaded)"
            }
            installerPackage !in TRUSTED_INSTALLERS -> {
                score += 10
                reasons += "Installed via unrecognized source: $installerPackage"
            }
        }

        return ScoreResult(score.coerceIn(0, 100), reasons)
    }

    private val EXECUTABLE_EXTENSIONS = setOf(
        "exe", "scr", "bat", "cmd", "vbs", "js", "jar", "apk", "msi", "com", "pif", "dll", "sh"
    )
    private val LURE_EXTENSIONS = setOf(
        "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "mp3", "mp4", "txt", "zip"
    )
    private val SUSPICIOUS_KEYWORDS = listOf("crack", "keygen", "patcher", "unlock_tool", "mod_apk_premium")

    fun scoreFile(fileName: String, entropy: Double, sizeBytes: Long): ScoreResult {
        val reasons = mutableListOf<String>()
        var score = 0

        val parts = fileName.split(".")
        val extension = parts.lastOrNull()?.lowercase(Locale.ROOT).orEmpty()

        if (extension in EXECUTABLE_EXTENSIONS) {
            score += 20
            reasons += "Executable or script file type (.$extension)"
        }

        if (parts.size >= 3) {
            val secondToLast = parts[parts.size - 2].lowercase(Locale.ROOT)
            if (secondToLast in LURE_EXTENSIONS && extension in EXECUTABLE_EXTENSIONS) {
                score += 35
                reasons += "Disguised double extension — looks like .$secondToLast but is really .$extension"
            }
        }

        if (sizeBytes > 4096) {
            when {
                entropy >= 7.5 -> {
                    score += 25
                    reasons += "Very high entropy (%.2f bits/byte) — likely packed, encrypted, or obfuscated".format(entropy)
                }
                entropy >= 7.0 -> {
                    score += 10
                    reasons += "Elevated entropy (%.2f bits/byte)".format(entropy)
                }
            }
        }

        val lowerName = fileName.lowercase(Locale.ROOT)
        if (SUSPICIOUS_KEYWORDS.any { it in lowerName }) {
            score += 10
            reasons += "File name matches a pattern commonly used by cracked/pirated software droppers"
        }

        return ScoreResult(score.coerceIn(0, 100), reasons)
    }
}
