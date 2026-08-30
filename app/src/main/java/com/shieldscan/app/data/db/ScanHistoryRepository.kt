package com.shieldscan.app.data.db

import com.shieldscan.app.data.model.AppFinding
import com.shieldscan.app.data.model.FileFinding
import com.shieldscan.app.data.model.Finding
import com.shieldscan.app.data.model.RiskLevel
import com.shieldscan.app.data.model.ScanSummary
import com.shieldscan.app.data.model.ScanType
import kotlinx.coroutines.flow.Flow

class ScanHistoryRepository(private val dao: ScanHistoryDao) {

    fun observeScans(): Flow<List<ScanRecordEntity>> = dao.observeScans()

    fun observeFindings(scanId: Long): Flow<List<FindingEntity>> = dao.observeFindingsForScan(scanId)

    suspend fun save(summary: ScanSummary): Long {
        val record = ScanRecordEntity(
            scanType = summary.scanType.name,
            startedAtEpochMs = summary.startedAtEpochMs,
            finishedAtEpochMs = summary.finishedAtEpochMs,
            itemsScanned = summary.itemsScanned,
            threatsFound = summary.threatsFound
        )
        val entities = summary.findings.map { it.toEntity(scanRecordId = 0) }
        return dao.insertScanWithFindings(record, entities)
    }

    suspend fun clearAll() = dao.deleteAllScans()

    suspend fun deleteScan(scanId: Long) = dao.deleteScan(scanId)

    private fun Finding.toEntity(scanRecordId: Long): FindingEntity = FindingEntity(
        scanRecordId = scanRecordId,
        kind = when (this) {
            is AppFinding -> "APP"
            is FileFinding -> "FILE"
        },
        displayName = displayName,
        subtitle = subtitle,
        sha256 = sha256,
        riskScore = riskScore,
        riskLevel = riskLevel.name,
        reasons = reasons.joinToString("||"),
        matchedSignatureName = matchedSignature?.name
    )
}

fun ScanRecordEntity.toScanTypeEnum(): ScanType = ScanType.valueOf(scanType)

fun FindingEntity.toRiskLevelEnum(): RiskLevel = RiskLevel.valueOf(riskLevel)

fun FindingEntity.reasonsList(): List<String> = reasons.split("||").filter { it.isNotBlank() }
