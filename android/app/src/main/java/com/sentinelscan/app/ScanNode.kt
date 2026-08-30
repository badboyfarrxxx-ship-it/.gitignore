package com.sentinelscan.app

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream

/**
 * Uniform view over a file/directory that may live behind a Storage Access
 * Framework tree (user-picked folder, no special permission) or as a raw
 * java.io.File (used once "All files access" has been granted). ScanEngine
 * walks a tree of these without caring which kind it is.
 */
sealed class ScanNode {
    abstract val name: String
    abstract val displayPath: String
    abstract val nodeType: NodeType
    abstract val parentIdentity: String?
    abstract val mimeType: String?

    abstract fun identityKey(): String
    abstract fun isDirectory(): Boolean
    abstract fun length(): Long
    abstract fun listChildren(context: Context): List<ScanNode>
    abstract fun openInputStream(context: Context): InputStream

    class Saf(
        private val document: DocumentFile,
        override val parentIdentity: String?,
        override val displayPath: String,
    ) : ScanNode() {
        override val name: String = document.name ?: "unnamed"
        override val nodeType = NodeType.SAF
        override val mimeType: String? = document.type

        override fun identityKey(): String = document.uri.toString()
        override fun isDirectory(): Boolean = document.isDirectory
        override fun length(): Long = document.length()

        override fun listChildren(context: Context): List<ScanNode> =
            document.listFiles()
                .filter { it.name != null }
                .map { child -> Saf(child, identityKey(), "$displayPath/${child.name}") }

        override fun openInputStream(context: Context): InputStream =
            context.contentResolver.openInputStream(document.uri)
                ?: throw IOException("Cannot open ${document.uri}")
    }

    class Raw(private val file: File, override val displayPath: String) : ScanNode() {
        override val name: String = file.name
        override val nodeType = NodeType.RAW
        override val parentIdentity: String? = file.parent
        override val mimeType: String? = null

        override fun identityKey(): String = file.absolutePath
        override fun isDirectory(): Boolean = file.isDirectory
        override fun length(): Long = file.length()

        override fun listChildren(context: Context): List<ScanNode> =
            (file.listFiles() ?: emptyArray()).map { child -> Raw(child, "$displayPath/${child.name}") }

        override fun openInputStream(context: Context): InputStream = FileInputStream(file)
    }

    companion object {
        fun fromTreeUri(context: Context, treeUri: Uri): ScanNode? {
            val doc = DocumentFile.fromTreeUri(context, treeUri) ?: return null
            return Saf(doc, null, doc.name ?: "root")
        }

        fun fromFile(root: File): ScanNode = Raw(root, root.absolutePath)
    }
}
