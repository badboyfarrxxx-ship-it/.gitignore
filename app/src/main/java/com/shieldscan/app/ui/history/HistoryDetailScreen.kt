package com.shieldscan.app.ui.history

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import com.shieldscan.app.data.db.reasonsList
import com.shieldscan.app.data.db.toRiskLevelEnum
import com.shieldscan.app.ui.MainViewModel
import com.shieldscan.app.ui.components.FindingCard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryDetailScreen(viewModel: MainViewModel, scanId: Long, onBack: () -> Unit) {
    val findingsFlow = remember(scanId) { viewModel.findingsFlow(scanId) }
    val findings by findingsFlow.collectAsState(initial = emptyList())

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan details") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (findings.isEmpty()) {
            Column(modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp)) {
                Text("Nothing was flagged in this scan.")
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(findings, key = { it.id }) { finding ->
                FindingCard(
                    name = finding.displayName,
                    subtitle = finding.subtitle,
                    riskLevel = finding.toRiskLevelEnum(),
                    riskScore = finding.riskScore,
                    reasons = finding.reasonsList(),
                    sha256 = finding.sha256,
                    signatureName = finding.matchedSignatureName
                )
            }
        }
    }
}
