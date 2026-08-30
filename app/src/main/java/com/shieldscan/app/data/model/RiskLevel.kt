package com.shieldscan.app.data.model

/**
 * Overall verdict for a scanned item, ordered from safest to most dangerous.
 * [score] is the lower bound (inclusive) of the 0-100 risk score range this level covers,
 * used by [RiskLevel.fromScore] to classify an aggregated heuristic score.
 */
enum class RiskLevel(val score: Int, val label: String) {
    CLEAN(0, "Clean"),
    LOW(20, "Low risk"),
    MEDIUM(45, "Suspicious"),
    HIGH(70, "High risk"),
    CRITICAL(90, "Malicious");

    companion object {
        fun fromScore(score: Int): RiskLevel =
            entries.sortedByDescending { it.score }.first { score >= it.score }
    }
}
