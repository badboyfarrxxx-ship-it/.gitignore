package com.sentinelscan.app

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.sentinelscan.app.databinding.ItemThreatBinding

class ThreatAdapter(
    private val items: List<Threat>,
    private val onQuarantineClick: (Threat) -> Unit,
) : RecyclerView.Adapter<ThreatAdapter.ViewHolder>() {

    class ViewHolder(val binding: ItemThreatBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemThreatBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val threat = items[position]
        val binding = holder.binding
        val context = binding.root.context

        binding.textFileName.text = threat.fileName
        binding.textPath.text = threat.displayPath
        binding.textDetections.text = threat.detections.joinToString(", ") { it.name }

        val severityColorRes = when (threat.severity) {
            "high" -> R.color.severity_high
            "medium" -> R.color.severity_medium
            else -> R.color.severity_low
        }
        binding.imageSeverity.setColorFilter(ContextCompat.getColor(context, severityColorRes))
        binding.textDetections.setTextColor(ContextCompat.getColor(context, severityColorRes))

        binding.buttonQuarantine.setOnClickListener { onQuarantineClick(threat) }
    }

    override fun getItemCount(): Int = items.size
}
