package com.sentinelscan.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.sentinelscan.app.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var db: SignatureDatabase
    private lateinit var adapter: ThreatAdapter

    private val currentThreats = mutableListOf<Threat>()
    private var lastFilesScanned = 0

    private val pickFolderLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            if (uri != null) {
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
                val root = ScanNode.fromTreeUri(this, uri)
                if (root != null) startScan(root) else toast("Could not open that folder")
            }
        }

    private val allFilesAccessLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            updateFullScanButtonState()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        adapter = ThreatAdapter(currentThreats) { threat -> quarantineOne(threat) }
        binding.recyclerThreats.layoutManager = LinearLayoutManager(this)
        binding.recyclerThreats.adapter = adapter

        db = SignatureDatabase.load(this)

        binding.buttonPickFolder.setOnClickListener { pickFolderLauncher.launch(null) }
        binding.buttonFullScan.setOnClickListener { onFullScanClicked() }
        binding.buttonQuarantineAll.setOnClickListener { quarantineAll() }
        binding.buttonViewQuarantine.setOnClickListener {
            startActivity(Intent(this, QuarantineActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        updateFullScanButtonState()
        refreshQuarantineCount()
    }

    private fun updateFullScanButtonState() {
        val granted = Environment.isExternalStorageManager()
        binding.buttonFullScan.text =
            if (granted) getString(R.string.scan_full_device) else getString(R.string.grant_full_access)
    }

    private fun onFullScanClicked() {
        if (Environment.isExternalStorageManager()) {
            startScan(ScanNode.fromFile(Environment.getExternalStorageDirectory()))
        } else {
            AlertDialog.Builder(this)
                .setTitle(R.string.permission_needed_title)
                .setMessage(R.string.permission_needed_message)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    val intent = Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:$packageName"),
                    )
                    allFilesAccessLauncher.launch(intent)
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun startScan(root: ScanNode) {
        setScanningUi(true)
        currentThreats.clear()
        adapter.notifyDataSetChanged()
        binding.bottomBar.visibility = View.GONE

        lifecycleScope.launch(Dispatchers.IO) {
            val report = try {
                ScanEngine.scan(applicationContext, root, db) { scanned, _ ->
                    runOnUiThread {
                        binding.textStatus.text = getString(R.string.scanning_in_progress, scanned)
                    }
                }
            } catch (e: Exception) {
                null
            }

            withContext(Dispatchers.Main) {
                setScanningUi(false)
                if (report == null) {
                    binding.textStatus.text = getString(R.string.scan_idle_hint)
                    toast("Scan failed")
                    return@withContext
                }
                lastFilesScanned = report.filesScanned
                currentThreats.clear()
                currentThreats.addAll(report.threats)
                adapter.notifyDataSetChanged()
                updateResultsUi()
            }
        }
    }

    private fun setScanningUi(scanning: Boolean) {
        binding.progressBar.visibility = if (scanning) View.VISIBLE else View.GONE
        binding.buttonPickFolder.isEnabled = !scanning
        binding.buttonFullScan.isEnabled = !scanning
        if (scanning) binding.textStatus.text = getString(R.string.scanning_in_progress, 0)
    }

    private fun updateResultsUi() {
        val hasThreats = currentThreats.isNotEmpty()
        binding.recyclerThreats.visibility = if (hasThreats) View.VISIBLE else View.GONE
        binding.emptyStateContainer.visibility = if (hasThreats) View.GONE else View.VISIBLE
        binding.bottomBar.visibility = if (hasThreats) View.VISIBLE else View.GONE

        val statusText = if (hasThreats) {
            getString(R.string.scan_complete_threats, currentThreats.size, lastFilesScanned)
        } else {
            getString(R.string.scan_complete_clean, lastFilesScanned)
        }
        binding.textStatus.text = statusText
        binding.textEmptyState.text = statusText
        binding.buttonQuarantineAll.text = getString(R.string.action_quarantine_all, currentThreats.size)
    }

    private fun quarantineOne(threat: Threat) {
        lifecycleScope.launch(Dispatchers.IO) {
            val error = try {
                QuarantineManager.quarantine(applicationContext, threat)
                null
            } catch (e: Exception) {
                e.message ?: "unknown error"
            }
            withContext(Dispatchers.Main) {
                if (error == null) {
                    toast(getString(R.string.quarantine_success, threat.fileName))
                    currentThreats.remove(threat)
                    adapter.notifyDataSetChanged()
                    updateResultsUi()
                    refreshQuarantineCount()
                } else {
                    toast(getString(R.string.quarantine_failure, threat.fileName, error))
                }
            }
        }
    }

    private fun quarantineAll() {
        val toQuarantine = currentThreats.toList()
        lifecycleScope.launch(Dispatchers.IO) {
            var succeeded = 0
            for (threat in toQuarantine) {
                try {
                    QuarantineManager.quarantine(applicationContext, threat)
                    succeeded += 1
                } catch (e: Exception) {
                    // Reflected in the succeeded/total summary toast below.
                }
            }
            withContext(Dispatchers.Main) {
                currentThreats.clear()
                adapter.notifyDataSetChanged()
                updateResultsUi()
                refreshQuarantineCount()
                toast("$succeeded/${toQuarantine.size} quarantined")
            }
        }
    }

    private fun refreshQuarantineCount() {
        lifecycleScope.launch(Dispatchers.IO) {
            val count = QuarantineManager.list(applicationContext).size
            withContext(Dispatchers.Main) {
                binding.buttonViewQuarantine.text = getString(R.string.view_quarantine, count)
            }
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}
