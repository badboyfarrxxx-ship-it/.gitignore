package com.sentinelscan.app

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.documentfile.provider.DocumentFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.time.Instant
import java.util.UUID

data class RestoreResult(val entry: QuarantineEntry, val restoredTo: String)

/**
 * Quarantines threats into app-private storage (already sandboxed by the
 * OS from every other app) with a JSON manifest, and can restore or
 * permanently purge them later.
 */
object QuarantineManager {
    private const val MANIFEST_NAME = "manifest.json"

    private fun quarantineDir(context: Context): File {
        val dir = File(context.filesDir, "quarantine")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private fun manifestFile(context: Context): File = File(quarantineDir(context), MANIFEST_NAME)

    private fun readManifest(context: Context): MutableList<QuarantineEntry> {
        val file = manifestFile(context)
        if (!file.exists()) return mutableListOf()
        val text = file.readText()
        if (text.isBlank()) return mutableListOf()
        val array = JSONArray(text)
        val list = mutableListOf<QuarantineEntry>()
        for (i in 0 until array.length()) list.add(entryFromJson(array.getJSONObject(i)))
        return list
    }

    private fun writeManifest(context: Context, entries: List<QuarantineEntry>) {
        val array = JSONArray()
        for (entry in entries) array.put(entryToJson(entry))
        manifestFile(context).writeText(array.toString())
    }

    private fun entryToJson(e: QuarantineEntry): JSONObject = JSONObject().apply {
        put("id", e.id)
        put("originalDisplayPath", e.originalDisplayPath)
        put("fileName", e.fileName)
        put("identityKey", e.identityKey)
        put("nodeType", e.nodeType.name)
        put("parentIdentity", e.parentIdentity ?: JSONObject.NULL)
        put("mimeType", e.mimeType ?: JSONObject.NULL)
        put("storedFileName", e.storedFileName)
        put("sha256", e.sha256)
        put("size", e.size)
        put("severity", e.severity)
        put("quarantinedAt", e.quarantinedAt)
        val detections = JSONArray()
        for (d in e.detections) {
            detections.put(
                JSONObject().apply {
                    put("id", d.id)
                    put("name", d.name)
                    put("severity", d.severity)
                    put("description", d.description)
                    put("source", d.source)
                }
            )
        }
        put("detections", detections)
    }

    private fun entryFromJson(obj: JSONObject): QuarantineEntry {
        val detections = mutableListOf<Detection>()
        val detectionsArray = obj.optJSONArray("detections") ?: JSONArray()
        for (i in 0 until detectionsArray.length()) {
            val d = detectionsArray.getJSONObject(i)
            detections.add(
                Detection(
                    id = d.getString("id"),
                    name = d.getString("name"),
                    severity = d.getString("severity"),
                    description = d.getString("description"),
                    source = d.getString("source"),
                )
            )
        }
        return QuarantineEntry(
            id = obj.getString("id"),
            originalDisplayPath = obj.getString("originalDisplayPath"),
            fileName = obj.getString("fileName"),
            identityKey = obj.getString("identityKey"),
            nodeType = NodeType.valueOf(obj.getString("nodeType")),
            parentIdentity = if (obj.isNull("parentIdentity")) null else obj.getString("parentIdentity"),
            mimeType = if (obj.isNull("mimeType")) null else obj.getString("mimeType"),
            storedFileName = obj.getString("storedFileName"),
            sha256 = obj.getString("sha256"),
            size = obj.getLong("size"),
            severity = obj.getString("severity"),
            detections = detections,
            quarantinedAt = obj.getString("quarantinedAt"),
        )
    }

    fun list(context: Context): List<QuarantineEntry> = readManifest(context)

    /** Copies the threat's bytes into quarantine, then deletes the original. */
    fun quarantine(context: Context, threat: Threat): QuarantineEntry {
        val bytes = readOriginalBytes(context, threat)

        val id = UUID.randomUUID().toString().replace("-", "").take(16)
        val storedFileName = "${id}_${threat.fileName}.quarantined"
        File(quarantineDir(context), storedFileName).writeBytes(bytes)

        if (!deleteOriginal(context, threat)) {
            File(quarantineDir(context), storedFileName).delete()
            throw IOException("Could not remove original file: ${threat.displayPath}")
        }

        val entry = QuarantineEntry(
            id = id,
            originalDisplayPath = threat.displayPath,
            fileName = threat.fileName,
            identityKey = threat.identityKey,
            nodeType = threat.nodeType,
            parentIdentity = threat.parentIdentity,
            mimeType = threat.mimeType,
            storedFileName = storedFileName,
            sha256 = threat.sha256,
            size = threat.size,
            severity = threat.severity,
            detections = threat.detections,
            quarantinedAt = Instant.now().toString(),
        )

        val entries = readManifest(context)
        entries.add(entry)
        writeManifest(context, entries)
        return entry
    }

    /** Restores a quarantined item to its original folder (renamed if that name is taken again). */
    fun restore(context: Context, id: String): RestoreResult {
        val entries = readManifest(context)
        val idx = entries.indexOfFirst { it.id == id }
        require(idx != -1) { "No quarantined item with id $id" }
        val entry = entries[idx]
        val bytes = File(quarantineDir(context), entry.storedFileName).readBytes()

        val restoredTo = when (entry.nodeType) {
            NodeType.RAW -> restoreRaw(entry, bytes)
            NodeType.SAF -> restoreSaf(context, entry, bytes)
        }

        entries.removeAt(idx)
        writeManifest(context, entries)
        File(quarantineDir(context), entry.storedFileName).delete()

        return RestoreResult(entry, restoredTo)
    }

    /** Permanently deletes a quarantined item. Cannot be undone. */
    fun purge(context: Context, id: String): QuarantineEntry {
        val entries = readManifest(context)
        val idx = entries.indexOfFirst { it.id == id }
        require(idx != -1) { "No quarantined item with id $id" }
        val entry = entries.removeAt(idx)
        File(quarantineDir(context), entry.storedFileName).delete()
        writeManifest(context, entries)
        return entry
    }

    private fun readOriginalBytes(context: Context, threat: Threat): ByteArray = when (threat.nodeType) {
        NodeType.RAW -> File(threat.identityKey).readBytes()
        NodeType.SAF -> {
            val uri = Uri.parse(threat.identityKey)
            context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw IOException("Cannot open $uri")
        }
    }

    private fun deleteOriginal(context: Context, threat: Threat): Boolean = when (threat.nodeType) {
        NodeType.RAW -> File(threat.identityKey).delete()
        NodeType.SAF -> DocumentsContract.deleteDocument(context.contentResolver, Uri.parse(threat.identityKey))
    }

    private fun restoreRaw(entry: QuarantineEntry, bytes: ByteArray): String {
        val parentPath = entry.parentIdentity ?: throw IOException("Missing parent folder for ${entry.fileName}")
        val parentDir = File(parentPath).apply { mkdirs() }
        var target = File(parentDir, entry.fileName)
        if (target.exists()) target = File(parentDir, "${entry.fileName}.restored-${System.currentTimeMillis()}")
        target.writeBytes(bytes)
        return target.absolutePath
    }

    private fun restoreSaf(context: Context, entry: QuarantineEntry, bytes: ByteArray): String {
        val parentUriString = entry.parentIdentity ?: throw IOException("Missing parent folder for ${entry.fileName}")
        val parentDoc = DocumentFile.fromSingleUri(context, Uri.parse(parentUriString))
            ?: throw IOException("Cannot resolve original folder")

        var displayName = entry.fileName
        if (parentDoc.findFile(displayName) != null) {
            displayName = "${entry.fileName}.restored-${System.currentTimeMillis()}"
        }

        val mime = entry.mimeType ?: "application/octet-stream"
        val newFile = parentDoc.createFile(mime, displayName) ?: throw IOException("Could not recreate file")
        context.contentResolver.openOutputStream(newFile.uri)?.use { it.write(bytes) }
            ?: throw IOException("Cannot write to ${newFile.uri}")

        val parentDisplay = entry.originalDisplayPath.substringBeforeLast('/', "")
        return if (parentDisplay.isEmpty()) displayName else "$parentDisplay/$displayName"
    }
}
