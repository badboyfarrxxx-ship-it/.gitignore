package com.shieldscan.app.data.db

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "findings",
    foreignKeys = [
        ForeignKey(
            entity = ScanRecordEntity::class,
            parentColumns = ["id"],
            childColumns = ["scanRecordId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index("scanRecordId")]
)
data class FindingEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scanRecordId: Long,
    val kind: String, // "APP" or "FILE"
    val displayName: String,
    val subtitle: String,
    val sha256: String,
    val riskScore: Int,
    val riskLevel: String,
    val reasons: String, // reasons joined with "||"
    val matchedSignatureName: String?
)
