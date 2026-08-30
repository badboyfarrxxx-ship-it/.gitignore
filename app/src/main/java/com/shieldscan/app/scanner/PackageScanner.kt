package com.shieldscan.app.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.shieldscan.app.data.model.AppFinding
import com.shieldscan.app.data.model.ScanSummary
import com.shieldscan.app.data.model.ScanType
import com.shieldscan.app.data.model.ThreatSignature
import com.shieldscan.app.data.signature.SignatureRepository
import com.shieldscan.app.util.HashUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream

/**
 * Scans every installed application: hashes its APK for a signature-database match and applies
 * [HeuristicsEngine] to its requested permissions and install source. Runs entirely on-device.
 */
class PackageScanner(
    private val context: Context,
    private val signatureRepository: SignatureRepository
) {
    suspend fun scanInstalledApps(
        onProgress: (current: Int, total: Int, label: String) -> Unit = { _, _, _ -> }
    ): ScanSummary = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val pm = context.packageManager
        val packages = getInstalledPackagesCompat(pm).filter { it.packageName != context.packageName }
        val findings = mutableListOf<AppFinding>()

        packages.forEachIndexed { index, packageInfo ->
            val label = runCatching {
                packageInfo.applicationInfo?.let { pm.getApplicationLabel(it).toString() }
            }.getOrNull() ?: packageInfo.packageName
            onProgress(index + 1, packages.size, label)

            scanSinglePackage(pm, packageInfo)?.let { findings += it }
        }

        ScanSummary(
            scanType = ScanType.INSTALLED_APPS,
            startedAtEpochMs = startedAt,
            finishedAtEpochMs = System.currentTimeMillis(),
            itemsScanned = packages.size,
            findings = findings.sortedByDescending { it.riskScore }
        )
    }

    private fun scanSinglePackage(pm: PackageManager, packageInfo: PackageInfo): AppFinding? {
        val appInfo = packageInfo.applicationInfo ?: return null
        val isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val label = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(packageInfo.packageName)
        val installer = getInstallerPackageCompat(pm, packageInfo.packageName)
        val permissions = packageInfo.requestedPermissions?.toList().orEmpty()

        var sha256 = ""
        var matchedSignature: ThreatSignature? = null
        runCatching {
            val apkFile = File(appInfo.sourceDir ?: return@runCatching)
            if (apkFile.exists() && apkFile.canRead()) {
                val result = FileInputStream(apkFile).use { HashUtils.digest(it) }
                sha256 = result.sha256
                matchedSignature = signatureRepository.lookup(sha256)
            }
        }

        val heuristic = HeuristicsEngine.scoreApp(
            isSystemApp = isSystemApp,
            installerPackage = installer,
            requestedPermissions = permissions,
            permissionWeightLookup = signatureRepository::permissionWeight
        )

        val reasons = heuristic.reasons.toMutableList()
        var score = heuristic.score
        val signature = matchedSignature
        if (signature != null) {
            score = 100
            reasons.add(0, "Matches known-malware signature: ${signature.name}")
        }

        // Keep the report focused: skip apps with nothing flagged at all.
        if (score == 0 && signature == null) return null

        return AppFinding(
            packageName = packageInfo.packageName,
            appLabel = label,
            versionName = packageInfo.versionName,
            apkSourcePath = appInfo.sourceDir.orEmpty(),
            isSystemApp = isSystemApp,
            installerPackage = installer,
            dangerousPermissions = permissions.filter { signatureRepository.permissionWeight(it) != null },
            sha256 = sha256,
            riskScore = score,
            reasons = reasons,
            matchedSignature = signature
        )
    }

    private fun getInstalledPackagesCompat(pm: PackageManager): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

    private fun getInstallerPackageCompat(pm: PackageManager, packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    } catch (e: PackageManager.NameNotFoundException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    }
}
