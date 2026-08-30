package com.shieldscan.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.shieldscan.app.data.model.RiskLevel
import com.shieldscan.app.ui.theme.ShieldDangerRed
import com.shieldscan.app.ui.theme.ShieldGreen
import com.shieldscan.app.ui.theme.ShieldWarningAmber

fun colorForRisk(level: RiskLevel): Color = when (level) {
    RiskLevel.CLEAN -> ShieldGreen
    RiskLevel.LOW -> Color(0xFF8BC34A)
    RiskLevel.MEDIUM -> ShieldWarningAmber
    RiskLevel.HIGH -> Color(0xFFFF7043)
    RiskLevel.CRITICAL -> ShieldDangerRed
}

@Composable
fun RiskBadge(level: RiskLevel, modifier: Modifier = Modifier) {
    val color = colorForRisk(level)
    Text(
        text = level.label,
        color = Color.Black,
        fontWeight = FontWeight.SemiBold,
        style = MaterialTheme.typography.labelMedium,
        modifier = modifier
            .background(color = color, shape = RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp)
    )
}
