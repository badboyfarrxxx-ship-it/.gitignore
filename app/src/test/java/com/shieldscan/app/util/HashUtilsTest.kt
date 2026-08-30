package com.shieldscan.app.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class HashUtilsTest {

    // The official EICAR antivirus test string — safe by design, used industry-wide to verify
    // a scanner's hash-matching path without handling real malware.
    private val eicarString =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"

    @Test
    fun `digest computes known SHA-256 for the EICAR test string`() {
        val result = HashUtils.digest(ByteArrayInputStream(eicarString.toByteArray(Charsets.US_ASCII)))

        assertEquals("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", result.sha256)
        assertEquals(68L, result.sizeBytes)
    }

    @Test
    fun `digest of empty stream has zero entropy`() {
        val result = HashUtils.digest(ByteArrayInputStream(ByteArray(0)))

        assertEquals(0L, result.sizeBytes)
        assertEquals(0.0, result.entropy, 0.0001)
    }

    @Test
    fun `digest of single repeated byte has zero entropy`() {
        val bytes = ByteArray(1024) { 0x41 }
        val result = HashUtils.digest(ByteArrayInputStream(bytes))

        assertEquals(0.0, result.entropy, 0.0001)
    }

    @Test
    fun `digest of uniformly random-looking bytes approaches max entropy`() {
        val bytes = ByteArray(256) { it.toByte() } // one of every byte value
        val result = HashUtils.digest(ByteArrayInputStream(bytes))

        assertTrue("expected entropy close to 8 bits/byte but was ${result.entropy}", result.entropy > 7.9)
    }
}
