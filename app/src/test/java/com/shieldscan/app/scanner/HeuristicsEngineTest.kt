package com.shieldscan.app.scanner

import com.shieldscan.app.data.signature.PermissionWeight
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HeuristicsEngineTest {

    private val weights = mapOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to PermissionWeight(
            "android.permission.BIND_ACCESSIBILITY_SERVICE", 25, "overlay/keylogging"
        ),
        "android.permission.SYSTEM_ALERT_WINDOW" to PermissionWeight(
            "android.permission.SYSTEM_ALERT_WINDOW", 15, "overlay attacks"
        ),
        "android.permission.READ_CONTACTS" to PermissionWeight(
            "android.permission.READ_CONTACTS", 5, "exfiltrate contacts"
        )
    )
    private val lookup: (String) -> PermissionWeight? = { weights[it] }

    @Test
    fun `system apps are always trusted regardless of permissions`() {
        val result = HeuristicsEngine.scoreApp(
            isSystemApp = true,
            installerPackage = null,
            requestedPermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            permissionWeightLookup = lookup
        )
        assertEquals(0, result.score)
    }

    @Test
    fun `sideloaded app with no risky permissions gets a modest score`() {
        val result = HeuristicsEngine.scoreApp(
            isSystemApp = false,
            installerPackage = null,
            requestedPermissions = emptyList(),
            permissionWeightLookup = lookup
        )
        assertEquals(20, result.score)
    }

    @Test
    fun `accessibility plus overlay combo adds a bonus on top of the permission weights`() {
        val result = HeuristicsEngine.scoreApp(
            isSystemApp = false,
            installerPackage = "com.android.vending",
            requestedPermissions = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            permissionWeightLookup = lookup
        )
        // 25 + 15 permission weights, +15 combo bonus, trusted installer adds nothing
        assertEquals(55, result.score)
        assertTrue(result.reasons.any { it.contains("banking-trojan", ignoreCase = true) })
    }

    @Test
    fun `app installed from the play store is not penalized for install source`() {
        val result = HeuristicsEngine.scoreApp(
            isSystemApp = false,
            installerPackage = "com.android.vending",
            requestedPermissions = listOf("android.permission.READ_CONTACTS"),
            permissionWeightLookup = lookup
        )
        assertEquals(5, result.score)
    }

    @Test
    fun `plain document file scores zero`() {
        val result = HeuristicsEngine.scoreFile("report.pdf", entropy = 3.2, sizeBytes = 50_000)
        assertEquals(0, result.score)
    }

    @Test
    fun `executable extension is flagged`() {
        val result = HeuristicsEngine.scoreFile("setup.exe", entropy = 2.0, sizeBytes = 50_000)
        assertEquals(20, result.score)
    }

    @Test
    fun `disguised double extension scores higher than the extension alone`() {
        val result = HeuristicsEngine.scoreFile("invoice.pdf.exe", entropy = 2.0, sizeBytes = 50_000)
        // 20 for .exe + 35 for the disguised double extension
        assertEquals(55, result.score)
    }

    @Test
    fun `high entropy content is flagged as likely packed or encrypted`() {
        val result = HeuristicsEngine.scoreFile("data.bin", entropy = 7.8, sizeBytes = 50_000)
        assertEquals(25, result.score)
    }

    @Test
    fun `small files are not penalized for entropy noise`() {
        val result = HeuristicsEngine.scoreFile("tiny.bin", entropy = 7.9, sizeBytes = 100)
        assertEquals(0, result.score)
    }
}
