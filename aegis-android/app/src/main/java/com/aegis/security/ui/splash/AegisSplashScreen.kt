package com.aegis.security.ui.splash

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.security.ui.theme.*
import kotlinx.coroutines.delay

/**
 * AEGIS SPLASH SCREEN
 *
 * Self-contained animated splash — shield scales in with a glow pulse,
 * then the wordmark fades in below it, then calls onFinished().
 *
 * TODO (logo swap): once the real logo is provided, replace the
 * Icons.Default.Shield icon below with an Image(painter = painterResource(R.drawable.aegis_logo))
 * — everything else (timing, glow, animation) stays the same.
 */
@Composable
fun AegisSplashScreen(onFinished: () -> Unit) {
    var startAnim by remember { mutableStateOf(false) }

    val shieldScale by animateFloatAsState(
        targetValue = if (startAnim) 1f else 0.3f,
        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessLow),
        label = "shieldScale"
    )
    val shieldAlpha by animateFloatAsState(
        targetValue = if (startAnim) 1f else 0f,
        animationSpec = tween(500),
        label = "shieldAlpha"
    )
    val textAlpha by animateFloatAsState(
        targetValue = if (startAnim) 1f else 0f,
        animationSpec = tween(600, delayMillis = 350),
        label = "textAlpha"
    )
    val taglineAlpha by animateFloatAsState(
        targetValue = if (startAnim) 1f else 0f,
        animationSpec = tween(600, delayMillis = 550),
        label = "taglineAlpha"
    )

    val glowPulse by rememberInfiniteTransition(label = "glow").animateFloat(
        initialValue = 0.85f,
        targetValue = 1.15f,
        animationSpec = infiniteRepeatable(tween(1400, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "glowPulse"
    )

    LaunchedEffect(Unit) {
        startAnim = true
        delay(2200)
        onFinished()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(Color(0xFF1A1245), AegisBgDeep),
                    center = Offset(0.5f, 0.4f),
                    radius = 900f
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {

            // Glow behind the shield
            Box(contentAlignment = Alignment.Center) {
                Box(
                    modifier = Modifier
                        .size(160.dp)
                        .scale(glowPulse)
                        .alpha(shieldAlpha * 0.5f)
                        .clip(CircleShape)
                        .background(
                            Brush.radialGradient(
                                listOf(AegisPurple.copy(alpha = 0.55f), Color.Transparent)
                            )
                        )
                )
                Box(
                    modifier = Modifier
                        .size(108.dp)
                        .scale(shieldScale)
                        .alpha(shieldAlpha)
                        .clip(CircleShape)
                        .background(
                            Brush.linearGradient(listOf(AegisPurple, AegisPurpleDark))
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    ShieldGlyph(tint = Color.White)
                }
            }

            Spacer(Modifier.height(28.dp))

            Text(
                "AEGIS",
                style = MaterialTheme.typography.displayLarge.copy(
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 6.sp,
                    fontSize = 34.sp
                ),
                color = Color.White,
                modifier = Modifier.alpha(textAlpha)
            )

            Spacer(Modifier.height(8.dp))

            Text(
                "Next-Gen Mobile Security",
                style = MaterialTheme.typography.bodyMedium,
                color = AegisPurpleLight,
                modifier = Modifier.alpha(taglineAlpha)
            )
        }
    }
}

/** Simple vector shield glyph — swap for the real logo drawable when available. */
@Composable
private fun ShieldGlyph(tint: Color) {
    androidx.compose.material3.Icon(
        imageVector = Icons.Default.Shield,
        contentDescription = "Aegis",
        tint = tint,
        modifier = Modifier.size(52.dp)
    )
}
