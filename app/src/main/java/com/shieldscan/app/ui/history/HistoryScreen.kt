package com.shieldscan.app.ui.history

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.shieldscan.app.data.db.ScanRecordEntity
import com.shieldscan.app.data.model.ScanType
import com.shieldscan.app.ui.MainViewModel
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val timeFormatter = DateTimeFormatter.ofPattern("MMM d, HH:mm")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(viewModel: MainViewModel, onOpenScan: (Long) -> Unit) {
    val history by viewModel.history.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan history") },
                actions = {
                    if (history.isNotEmpty()) {
                        IconButton(onClick = { viewModel.clearHistory() }) {
                            Icon(Icons.Filled.Delete, contentDescription = "Clear history")
                        }
                    }
                }
            )
        }
    ) { padding ->
        if (history.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp)) {
                Text("No scans yet. Run a scan from the Home tab to see it here.")
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(history, key = { it.id }) { record ->
                HistoryRow(record = record, onClick = { onOpenScan(record.id) })
            }
        }
    }
}

@Composable
private fun HistoryRow(record: ScanRecordEntity, onClick: () -> Unit) {
    val typeLabel = if (ScanType.valueOf(record.scanType) == ScanType.INSTALLED_APPS) "Installed apps" else "Folder scan"
    val dateLabel = remember(record.finishedAtEpochMs) {
        Instant.ofEpochMilli(record.finishedAtEpochMs).atZone(ZoneId.systemDefault()).format(timeFormatter)
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(typeLabel, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(dateLabel, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("${record.itemsScanned} items scanned", style = MaterialTheme.typography.bodySmall)
            }
            Text(
                text = if (record.threatsFound > 0) "${record.threatsFound} flagged" else "Clean",
                fontWeight = FontWeight.Bold,
                color = if (record.threatsFound > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
            )
        }
    }
}
