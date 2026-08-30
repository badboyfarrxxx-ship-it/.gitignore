package com.shieldscan.app.ui

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.shieldscan.app.ShieldScanApp
import com.shieldscan.app.data.db.FindingEntity
import com.shieldscan.app.data.db.ScanHistoryRepository
import com.shieldscan.app.data.db.ScanRecordEntity
import com.shieldscan.app.data.model.ScanSummary
import com.shieldscan.app.data.model.ScanType
import com.shieldscan.app.data.signature.ImportResult
import com.shieldscan.app.data.signature.SignatureRepository
import com.shieldscan.app.scanner.FileScanner
import com.shieldscan.app.scanner.PackageScanner
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

sealed interface ScanUiState {
    data object Idle : ScanUiState
    data class Running(val current: Int, val total: Int, val label: String, val scanType: ScanType) : ScanUiState
    data class Completed(val summary: ScanSummary) : ScanUiState
    data class Error(val message: String) : ScanUiState
}

data class SignatureInfo(val builtIn: Int, val custom: Int) {
    val total: Int get() = builtIn + custom
}

class MainViewModel(
    private val packageScanner: PackageScanner,
    private val fileScanner: FileScanner,
    private val scanHistoryRepository: ScanHistoryRepository,
    private val signatureRepository: SignatureRepository
) : ViewModel() {

    private val _scanState = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val scanState: StateFlow<ScanUiState> = _scanState.asStateFlow()

    val history: StateFlow<List<ScanRecordEntity>> = scanHistoryRepository.observeScans()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _signatureInfo = MutableStateFlow(SignatureInfo(0, 0))
    val signatureInfo: StateFlow<SignatureInfo> = _signatureInfo.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    init {
        viewModelScope.launch {
            signatureRepository.initialize()
            refreshSignatureInfo()
        }
    }

    private fun refreshSignatureInfo() {
        _signatureInfo.value = SignatureInfo(
            builtIn = signatureRepository.builtInSignatureCount(),
            custom = signatureRepository.customSignatureCount()
        )
    }

    fun startAppScan() {
        if (_scanState.value is ScanUiState.Running) return
        viewModelScope.launch {
            _scanState.value = ScanUiState.Running(0, 0, "Starting…", ScanType.INSTALLED_APPS)
            runCatching {
                packageScanner.scanInstalledApps { current, total, label ->
                    _scanState.value = ScanUiState.Running(current, total, label, ScanType.INSTALLED_APPS)
                }
            }.onSuccess { summary ->
                scanHistoryRepository.save(summary)
                _scanState.value = ScanUiState.Completed(summary)
            }.onFailure { error ->
                _scanState.value = ScanUiState.Error(error.message ?: "App scan failed")
            }
        }
    }

    fun startFileScan(treeUri: Uri) {
        if (_scanState.value is ScanUiState.Running) return
        viewModelScope.launch {
            _scanState.value = ScanUiState.Running(0, -1, "Starting…", ScanType.FILES)
            runCatching {
                fileScanner.scanTree(treeUri) { scanned, label ->
                    _scanState.value = ScanUiState.Running(scanned, -1, label, ScanType.FILES)
                }
            }.onSuccess { summary ->
                scanHistoryRepository.save(summary)
                _scanState.value = ScanUiState.Completed(summary)
            }.onFailure { error ->
                _scanState.value = ScanUiState.Error(error.message ?: "File scan failed")
            }
        }
    }

    fun resetScanState() {
        _scanState.value = ScanUiState.Idle
    }

    fun findingsFlow(scanId: Long): Flow<List<FindingEntity>> = scanHistoryRepository.observeFindings(scanId)

    fun deleteScan(scanId: Long) {
        viewModelScope.launch { scanHistoryRepository.deleteScan(scanId) }
    }

    fun clearHistory() {
        viewModelScope.launch { scanHistoryRepository.clearAll() }
    }

    fun importSignatures(uri: Uri) {
        viewModelScope.launch {
            when (val result = signatureRepository.importSignatures(uri)) {
                is ImportResult.Success -> {
                    val skippedNote = if (result.skippedInvalid > 0) " (${result.skippedInvalid} invalid skipped)" else ""
                    _statusMessage.value = "Imported ${result.added} signatures$skippedNote"
                    refreshSignatureInfo()
                }
                is ImportResult.Failure -> _statusMessage.value = result.message
            }
        }
    }

    fun clearCustomSignatures() {
        viewModelScope.launch {
            signatureRepository.clearCustomSignatures()
            refreshSignatureInfo()
            _statusMessage.value = "Custom signatures cleared"
        }
    }

    fun consumeStatusMessage() {
        _statusMessage.value = null
    }

    class Factory(private val app: ShieldScanApp) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(MainViewModel::class.java))
            return MainViewModel(
                packageScanner = app.packageScanner,
                fileScanner = app.fileScanner,
                scanHistoryRepository = app.scanHistoryRepository,
                signatureRepository = app.signatureRepository
            ) as T
        }
    }
}
