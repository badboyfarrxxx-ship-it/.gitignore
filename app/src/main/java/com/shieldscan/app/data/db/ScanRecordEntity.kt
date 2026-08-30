package com.shieldscan.app.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_records")
data class ScanRecordEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scanType: String,
    val startedAtEpochMs: Long,
    val finishedAtEpochMs: Long,
    val itemsScanned: Int,
    val threatsFound: Int
)
