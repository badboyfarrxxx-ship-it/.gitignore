package com.shieldscan.app.ui.home

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.shieldscan.app.data.model.ScanType
import com.shieldscan.app.ui.MainViewModel
import com.shieldscan.app.ui.ScanUiState
import com.shieldscan.app.ui.theme.ShieldGreen

@Composable
fun HomeScreen(
    viewModel: MainViewModel,
    onScanCompleted: () -> Unit
) {
    val scanState by viewModel.scanState.collectAsState()
    val signatureInfo by viewModel.signatureInfo.collectAsState()
    val history by viewModel.history.collectAsState()

    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            viewModel.startFileScan(uri)
        }
    }

    LaunchedEffect(scanState) {
        if (scanState is ScanUiState.Completed) onScanCompleted()
    }

    val isRunning = scanState is ScanUiState.Running

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(Icons.Filled.Shield, contentDescription = null, tint = ShieldGreen, modifier = Modifier.size(32.dp))
            Column {
                Text("ShieldScan", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text(
                    "On-device malware & permission scanner",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Signature database", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(
                    "${signatureInfo.total} known-threat hashes loaded (${signatureInfo.builtIn} built-in, ${signatureInfo.custom} imported)",
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    "${history.size} scan${if (history.size == 1) "" else "s"} in history",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        if (isRunning) {
            val running = scanState as ScanUiState.Running
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                        Text(
                            if (running.scanType == ScanType.INSTALLED_APPS) "Scanning installed apps…" else "Scanning files…",
                            style = MaterialTheme.typography.titleSmall
                        )
                    }
                    if (running.total > 0) {
                        LinearProgressIndicator(
                            progress = { running.current.toFloat() / running.total.toFloat() },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Text("${running.current} / ${running.total} — ${running.label}", style = MaterialTheme.typography.bodySmall)
                    } else {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Text("${running.current} scanned — ${running.label}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        ScanActionCard(
            icon = Icons.Filled.Apps,
            title = "Scan installed apps",
            description = "Hashes every installed app's APK against the signature database and flags risky permission combinations, sideloading, and known abuse patterns.",
            buttonLabel = "Scan apps",
            enabled = !isRunning,
            onClick = { viewModel.startAppScan() }
        )

        ScanActionCard(
            icon = Icons.Filled.Folder,
            title = "Scan a folder",
            description = "Pick a folder (e.g. Downloads) to recursively hash its files, check them against the signature database, and flag disguised extensions or high-entropy (packed/encrypted) content.",
            buttonLabel = "Choose folder & scan",
            enabled = !isRunning,
            onClick = { folderPicker.launch(null) }
        )

        if (scanState is ScanUiState.Error) {
            Text(
                text = "Last scan failed: ${(scanState as ScanUiState.Error).message}",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Spacer(modifier = Modifier.height(8.dp))
        Text(
            "ShieldScan runs entirely on-device and never uploads your files or app list anywhere. " +
                "Heuristic findings are signals for you to review, not a guaranteed verdict.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ScanActionCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    buttonLabel: String,
    enabled: Boolean,
    onClick: () -> Unit
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(icon, contentDescription = null, tint = ShieldGreen)
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            }
            Text(description, style = MaterialTheme.typography.bodySmall)
            Button(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) {
                Text(buttonLabel)
            }
        }
    }
}
