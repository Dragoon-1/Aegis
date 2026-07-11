package com.aegis.security.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// ── Brand colors ──────────────────────────────────────────────────────────────
val AegisPurple      = Color(0xFF534AB7)
val AegisPurpleLight = Color(0xFF8B7FF5)
val AegisPurpleDark  = Color(0xFF2E276E)
val AegisTeal        = Color(0xFF0F6E56)
val AegisTealLight   = Color(0xFF1DB48B)
val AegisCoralRed    = Color(0xFFE05C30)
val AegisAmber       = Color(0xFFBA7517)
val AegisGreen       = Color(0xFF2D9E5F)
val AegisBgDeep      = Color(0xFF0D0D1A)
val AegisSurface     = Color(0xFF12122A)
val AegisSurfaceVar  = Color(0xFF1C1C35)
val AegisOnBg        = Color(0xFFE8E8F0)
val AegisSubtext     = Color(0xFF8888AA)
val AegisOutline     = Color(0xFF3A3A5C)

// ── Dark colour scheme (default — security app is always dark) ────────────────
private val DarkColorScheme = darkColorScheme(
    primary              = AegisPurple,
    onPrimary            = Color.White,
    primaryContainer     = AegisPurpleDark,
    onPrimaryContainer   = AegisPurpleLight,
    secondary            = AegisTeal,
    onSecondary          = Color.White,
    secondaryContainer   = Color(0xFF063D2F),
    onSecondaryContainer = AegisTealLight,
    tertiary             = AegisAmber,
    onTertiary           = Color.White,
    error                = AegisCoralRed,
    onError              = Color.White,
    errorContainer       = Color(0xFF4A1A0A),
    onErrorContainer     = Color(0xFFFFBBAA),
    background           = AegisBgDeep,
    onBackground         = AegisOnBg,
    surface              = AegisSurface,
    onSurface            = AegisOnBg,
    surfaceVariant       = AegisSurfaceVar,
    onSurfaceVariant     = Color(0xFFB0B0C8),
    outline              = AegisOutline,
    outlineVariant       = Color(0xFF2A2A48),
)

// ── Typography ────────────────────────────────────────────────────────────────
val AegisTypography = Typography(
    displayLarge  = TextStyle(fontSize = 32.sp, fontWeight = FontWeight.Bold,   letterSpacing = (-0.5).sp),
    displayMedium = TextStyle(fontSize = 28.sp, fontWeight = FontWeight.SemiBold),
    headlineLarge = TextStyle(fontSize = 24.sp, fontWeight = FontWeight.SemiBold),
    headlineMedium= TextStyle(fontSize = 20.sp, fontWeight = FontWeight.Medium),
    titleLarge    = TextStyle(fontSize = 18.sp, fontWeight = FontWeight.Medium),
    titleMedium   = TextStyle(fontSize = 16.sp, fontWeight = FontWeight.Medium),
    titleSmall    = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.Medium),
    bodyLarge     = TextStyle(fontSize = 16.sp, fontWeight = FontWeight.Normal),
    bodyMedium    = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.Normal),
    bodySmall     = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.Normal),
    labelLarge    = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.sp),
    labelMedium   = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.Medium,  letterSpacing = 0.5.sp),
    labelSmall    = TextStyle(fontSize = 11.sp, fontWeight = FontWeight.Medium,  letterSpacing = 0.5.sp),
)

// ── Theme composable ──────────────────────────────────────────────────────────
@Composable
fun AegisTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography  = AegisTypography,
        content     = content
    )
}
