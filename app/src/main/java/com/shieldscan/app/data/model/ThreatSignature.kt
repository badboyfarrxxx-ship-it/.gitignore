package com.shieldscan.app.data.model

/** A single known-malicious hash entry loaded from the bundled signature database. */
data class ThreatSignature(
    val sha256: String,
    val name: String,
    val category: String,
    val severity: String,
    val source: String
)
