package com.shieldscan.app.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanHistoryDao {

    @Insert
    suspend fun insertScan(scan: ScanRecordEntity): Long

    @Insert
    suspend fun insertFindings(findings: List<FindingEntity>)

    @Query("SELECT * FROM scan_records ORDER BY finishedAtEpochMs DESC")
    fun observeScans(): Flow<List<ScanRecordEntity>>

    @Query("SELECT * FROM findings WHERE scanRecordId = :scanId ORDER BY riskScore DESC")
    fun observeFindingsForScan(scanId: Long): Flow<List<FindingEntity>>

    @Query("DELETE FROM scan_records")
    suspend fun deleteAllScans()

    @Query("DELETE FROM scan_records WHERE id = :scanId")
    suspend fun deleteScan(scanId: Long)

    @Transaction
    suspend fun insertScanWithFindings(scan: ScanRecordEntity, findings: List<FindingEntity>): Long {
        val scanId = insertScan(scan)
        if (findings.isNotEmpty()) {
            insertFindings(findings.map { it.copy(scanRecordId = scanId) })
        }
        return scanId
    }
}
