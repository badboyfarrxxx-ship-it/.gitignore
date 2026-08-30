package com.shieldscan.app.ui.settings

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.shieldscan.app.ui.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: MainViewModel) {
    val signatureInfo by viewModel.signatureInfo.collectAsState()
    val statusMessage by viewModel.statusMessage.collectAsState()

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { viewModel.importSignatures(it) } }

    Scaffold(topBar = { TopAppBar(title = { Text("Settings") }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Signature database", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text("${signatureInfo.builtIn} built-in signatures")
                    Text("${signatureInfo.custom} imported signatures")
                    Text(
                        "Import a SHA-256 hash feed (JSON or CSV, one hash per line) from a threat-intel " +
                            "source you trust. Nothing is ever downloaded automatically — ShieldScan has no " +
                            "network permission and never phones home.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Button(onClick = { importLauncher.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                        Text("Import signature feed")
                    }
                    OutlinedButton(
                        onClick = { viewModel.clearCustomSignatures() },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = signatureInfo.custom > 0
                    ) {
                        Text("Clear imported signatures")
                    }
                }
            }

            if (statusMessage != null) {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                    Text(statusMessage ?: "", modifier = Modifier.padding(16.dp))
                }
                LaunchedEffect(statusMessage) {
                    kotlinx.coroutines.delay(4000)
                    viewModel.consumeStatusMessage()
                }
            }

            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("About ShieldScan", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(
                        "ShieldScan combines SHA-256 signature matching against a hash database with " +
                            "on-device heuristics (dangerous permission combinations, sideloading, disguised " +
                            "file extensions, and content entropy) to flag potentially malicious apps and files. " +
                            "It is a defensive aid, not a certified antivirus product — always corroborate a " +
                            "critical finding before acting on it (e.g. uninstalling an app or deleting a file).",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}
