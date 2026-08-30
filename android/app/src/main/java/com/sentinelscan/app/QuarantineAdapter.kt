package com.sentinelscan.app

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.sentinelscan.app.databinding.ItemQuarantineBinding

class QuarantineAdapter(
    private val items: MutableList<QuarantineEntry>,
    private val onRestoreClick: (QuarantineEntry) -> Unit,
    private val onDeleteClick: (QuarantineEntry) -> Unit,
) : RecyclerView.Adapter<QuarantineAdapter.ViewHolder>() {

    class ViewHolder(val binding: ItemQuarantineBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemQuarantineBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val entry = items[position]
        val binding = holder.binding

        binding.textFileName.text = entry.fileName
        binding.textPath.text = entry.originalDisplayPath
        binding.textQuarantinedAt.text =
            binding.root.context.getString(R.string.quarantined_at, entry.quarantinedAt)

        binding.buttonRestore.setOnClickListener { onRestoreClick(entry) }
        binding.buttonDelete.setOnClickListener { onDeleteClick(entry) }
    }

    override fun getItemCount(): Int = items.size

    fun removeEntry(entry: QuarantineEntry) {
        val index = items.indexOfFirst { it.id == entry.id }
        if (index != -1) {
            items.removeAt(index)
            notifyItemRemoved(index)
        }
    }
}
