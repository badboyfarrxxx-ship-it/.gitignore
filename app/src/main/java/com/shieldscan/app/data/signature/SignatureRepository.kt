package com.shieldscan.app.data.signature

import android.content.Context
import android.net.Uri
import com.shieldscan.app.data.model.ThreatSignature
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

sealed class ImportResult {
    data class Success(val added: Int, val skippedInvalid: Int) : ImportResult()
    data class Failure(val message: String) : ImportResult()
}

/**
 * Loads the bundled malware-hash signature set and dangerous-permission weight table from
 * assets, and layers in any user-imported signatures persisted under the app's private files
 * directory. Everything runs fully offline: nothing here ever makes a network call.
 */
class SignatureRepository(private val context: Context) {

    private val mutex = Mutex()
    private val builtIn = LinkedHashMap<String, ThreatSignature>()
    private val custom = LinkedHashMap<String, ThreatSignature>()
    private val permissionWeights = LinkedHashMap<String, PermissionWeight>()
    private var initialized = false

    private val customSignaturesFile: File
        get() = File(context.filesDir, "custom_signatures.json")

    suspend fun initialize() = withContext(Dispatchers.IO) {
        mutex.withLock {
            if (initialized) return@withContext
            loadBuiltInSignatures()
            loadPermissionWeights()
            loadCustomSignaturesFromDisk()
            initialized = true
        }
    }

    private fun loadBuiltInSignatures() {
        val text = context.assets.open("signatures/malware_hashes.json").bufferedReader().use { it.readText() }
        val root = JSONObject(text)
        val array = root.getJSONArray("signatures")
        for (i in 0 until array.length()) {
            val entry = array.getJSONObject(i)
            val sig = entry.toThreatSignature() ?: continue
            builtIn[sig.sha256.lowercase()] = sig
        }
    }

    private fun loadPermissionWeights() {
        val text = context.assets.open("signatures/dangerous_permissions.json").bufferedReader().use { it.readText() }
        val root = JSONObject(text)
        val array = root.getJSONArray("permissions")
        for (i in 0 until array.length()) {
            val entry = array.getJSONObject(i)
            val permission = entry.optString("permission")
            if (permission.isBlank()) continue
            permissionWeights[permission] = PermissionWeight(
                permission = permission,
                weight = entry.optInt("weight", 0),
                reason = entry.optString("reason", "")
            )
        }
    }

    private fun loadCustomSignaturesFromDisk() {
        val file = customSignaturesFile
        if (!file.exists()) return
        runCatching {
            val root = JSONObject(file.readText())
            val array = root.getJSONArray("signatures")
            for (i in 0 until array.length()) {
                val sig = array.getJSONObject(i).toThreatSignature() ?: continue
                custom[sig.sha256.lowercase()] = sig
            }
        }
    }

    private fun persistCustomSignatures() {
        val array = JSONArray()
        for (sig in custom.values) {
            array.put(
                JSONObject()
                    .put("sha256", sig.sha256)
                    .put("name", sig.name)
                    .put("category", sig.category)
                    .put("severity", sig.severity)
                    .put("source", sig.source)
            )
        }
        val root = JSONObject().put("signatures", array)
        customSignaturesFile.writeText(root.toString())
    }

    fun lookup(sha256: String): ThreatSignature? {
        val key = sha256.lowercase()
        return custom[key] ?: builtIn[key]
    }

    fun permissionWeight(permission: String): PermissionWeight? = permissionWeights[permission]

    fun allPermissionWeights(): List<PermissionWeight> = permissionWeights.values.toList()

    fun builtInSignatureCount(): Int = builtIn.size

    fun customSignatureCount(): Int = custom.size

    fun totalSignatureCount(): Int = (builtIn.keys + custom.keys).size

    /**
     * Imports a hash feed from [uri]. Accepts either the app's native JSON shape
     * (`{"signatures":[{"sha256":...}, ...]}` or a bare JSON array of the same objects)
     * or a plain-text CSV/newline list of `sha256[,name]` per line, which is the common
     * export shape of most public threat-intel hash feeds.
     */
    suspend fun importSignatures(uri: Uri): ImportResult = withContext(Dispatchers.IO) {
        val text = runCatching {
            context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        }.getOrNull() ?: return@withContext ImportResult.Failure("Could not read the selected file")

        val parsed = parseAsJson(text) ?: parseAsCsv(text)
        if (parsed.isEmpty()) {
            return@withContext ImportResult.Failure("No valid SHA-256 signatures found in file")
        }

        var added = 0
        var skipped = 0
        mutex.withLock {
            for (sig in parsed) {
                if (sig.sha256.length != 64 || !sig.sha256.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                    skipped++
                    continue
                }
                custom[sig.sha256.lowercase()] = sig
                added++
            }
            persistCustomSignatures()
        }
        ImportResult.Success(added = added, skippedInvalid = skipped)
    }

    suspend fun clearCustomSignatures() = withContext(Dispatchers.IO) {
        mutex.withLock {
            custom.clear()
            if (customSignaturesFile.exists()) customSignaturesFile.delete()
        }
    }

    private fun parseAsJson(text: String): List<ThreatSignature>? = runCatching {
        val trimmed = text.trim()
        val array: JSONArray = when {
            trimmed.startsWith("[") -> JSONArray(trimmed)
            trimmed.startsWith("{") -> JSONObject(trimmed).getJSONArray("signatures")
            else -> return null
        }
        (0 until array.length()).mapNotNull { array.getJSONObject(it).toThreatSignature() }
    }.getOrNull()

    private fun parseAsCsv(text: String): List<ThreatSignature> =
        text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { line ->
                val parts = line.split(",", ";", "\t").map { it.trim() }
                val hash = parts.getOrNull(0) ?: return@mapNotNull null
                val name = parts.getOrNull(1)?.ifBlank { null } ?: "Imported-Signature"
                ThreatSignature(
                    sha256 = hash,
                    name = name,
                    category = "imported",
                    severity = "high",
                    source = "user-imported feed"
                )
            }.toList()

    private fun JSONObject.toThreatSignature(): ThreatSignature? {
        val sha256 = optString("sha256").ifBlank { return null }
        return ThreatSignature(
            sha256 = sha256,
            name = optString("name").ifBlank { "Unnamed-Signature" },
            category = optString("category").ifBlank { "unknown" },
            severity = optString("severity").ifBlank { "high" },
            source = optString("source").ifBlank { "imported" }
        )
    }
}
