package com.shieldscan.app.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskLevelTest {

    @Test
    fun `boundary scores classify to the expected level`() {
        assertEquals(RiskLevel.CLEAN, RiskLevel.fromScore(0))
        assertEquals(RiskLevel.CLEAN, RiskLevel.fromScore(19))
        assertEquals(RiskLevel.LOW, RiskLevel.fromScore(20))
        assertEquals(RiskLevel.LOW, RiskLevel.fromScore(44))
        assertEquals(RiskLevel.MEDIUM, RiskLevel.fromScore(45))
        assertEquals(RiskLevel.HIGH, RiskLevel.fromScore(70))
        assertEquals(RiskLevel.CRITICAL, RiskLevel.fromScore(90))
        assertEquals(RiskLevel.CRITICAL, RiskLevel.fromScore(100))
    }

    @Test
    fun `levels are ordered from safest to most dangerous`() {
        assertTrue(RiskLevel.CLEAN < RiskLevel.LOW)
        assertTrue(RiskLevel.LOW < RiskLevel.MEDIUM)
        assertTrue(RiskLevel.MEDIUM < RiskLevel.HIGH)
        assertTrue(RiskLevel.HIGH < RiskLevel.CRITICAL)
    }
}
