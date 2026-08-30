package com.shieldscan.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val ShieldGreen = Color(0xFF4CAF50)
val ShieldGreenDark = Color(0xFF1B5E20)
val ShieldDangerRed = Color(0xFFE53935)
val ShieldWarningAmber = Color(0xFFFFA000)
val ShieldBackgroundDark = Color(0xFF0E1F13)
val ShieldSurfaceDark = Color(0xFF162B1B)

private val DarkColors = darkColorScheme(
    primary = ShieldGreen,
    onPrimary = Color.Black,
    secondary = ShieldWarningAmber,
    background = ShieldBackgroundDark,
    surface = ShieldSurfaceDark,
    error = ShieldDangerRed
)

private val LightColors = lightColorScheme(
    primary = ShieldGreenDark,
    onPrimary = Color.White,
    secondary = ShieldWarningAmber,
    error = ShieldDangerRed
)

@Composable
fun ShieldScanTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColors else LightColors
    MaterialTheme(
        colorScheme = colorScheme,
        typography = MaterialTheme.typography,
        content = content
    )
}
