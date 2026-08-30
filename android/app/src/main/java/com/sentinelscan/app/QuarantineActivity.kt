package com.sentinelscan.app

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.sentinelscan.app.databinding.ActivityQuarantineBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class QuarantineActivity : AppCompatActivity() {

    private lateinit var binding: ActivityQuarantineBinding
    private lateinit var adapter: QuarantineAdapter
    private val entries = mutableListOf<QuarantineEntry>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityQuarantineBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        binding.toolbar.setNavigationOnClickListener { finish() }

        adapter = QuarantineAdapter(entries, ::onRestoreClick, ::onDeleteClick)
        binding.recyclerQuarantine.layoutManager = LinearLayoutManager(this)
        binding.recyclerQuarantine.adapter = adapter

        loadEntries()
    }

    private fun loadEntries() {
        lifecycleScope.launch(Dispatchers.IO) {
            val loaded = QuarantineManager.list(applicationContext)
            withContext(Dispatchers.Main) {
                entries.clear()
                entries.addAll(loaded)
                adapter.notifyDataSetChanged()
                updateEmptyState()
            }
        }
    }

    private fun updateEmptyState() {
        val hasEntries = entries.isNotEmpty()
        binding.recyclerQuarantine.visibility = if (hasEntries) View.VISIBLE else View.GONE
        binding.textEmptyQuarantine.visibility = if (hasEntries) View.GONE else View.VISIBLE
    }

    private fun onRestoreClick(entry: QuarantineEntry) {
        lifecycleScope.launch(Dispatchers.IO) {
            var result: RestoreResult? = null
            var error: String? = null
            try {
                result = QuarantineManager.restore(applicationContext, entry.id)
            } catch (e: Exception) {
                error = e.message ?: "unknown error"
            }
            withContext(Dispatchers.Main) {
                if (result != null) {
                    toast(getString(R.string.restore_success, result.restoredTo))
                    adapter.removeEntry(entry)
                    updateEmptyState()
                } else {
                    toast(getString(R.string.restore_failure, entry.fileName, error ?: "unknown error"))
                }
            }
        }
    }

    private fun onDeleteClick(entry: QuarantineEntry) {
        AlertDialog.Builder(this)
            .setTitle(R.string.action_delete_forever)
            .setMessage(entry.fileName)
            .setPositiveButton(android.R.string.ok) { _, _ -> performDelete(entry) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun performDelete(entry: QuarantineEntry) {
        lifecycleScope.launch(Dispatchers.IO) {
            QuarantineManager.purge(applicationContext, entry.id)
            withContext(Dispatchers.Main) {
                toast(getString(R.string.delete_success, entry.fileName))
                adapter.removeEntry(entry)
                updateEmptyState()
            }
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}
