package com.shieldscan.app.ui.results

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.shieldscan.app.data.model.Finding
import com.shieldscan.app.data.model.ScanSummary
import com.shieldscan.app.ui.MainViewModel
import com.shieldscan.app.ui.ScanUiState
import com.shieldscan.app.ui.components.FindingCard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanResultsScreen(viewModel: MainViewModel, onBack: () -> Unit) {
    val scanState by viewModel.scanState.collectAsState()
    val summary = (scanState as? ScanUiState.Completed)?.summary

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan results") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        if (summary == null) {
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
            ) {
                Text("No scan results yet — run a scan from the Home tab.")
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item { SummaryHeader(summary) }

            if (summary.findings.isEmpty()) {
                item {
                    Text(
                        "✅ Nothing suspicious found across ${summary.itemsScanned} scanned items.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            } else {
                items(summary.findings) { finding: Finding ->
                    FindingCard(
                        name = finding.displayName,
                        subtitle = finding.subtitle,
                        riskLevel = finding.riskLevel,
                        riskScore = finding.riskScore,
                        reasons = finding.reasons,
                        sha256 = finding.sha256,
                        signatureName = finding.matchedSignature?.name
                    )
                }
            }
        }
    }
}

@Composable
fun SummaryHeader(summary: ScanSummary) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Items scanned", style = MaterialTheme.typography.bodyMedium)
                Text("${summary.itemsScanned}", fontWeight = FontWeight.Bold)
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Threats / suspicious", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "${summary.threatsFound}",
                    fontWeight = FontWeight.Bold,
                    color = if (summary.threatsFound > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Duration", style = MaterialTheme.typography.bodyMedium)
                Text("${summary.durationMs / 1000}s")
            }
        }
    }
}
