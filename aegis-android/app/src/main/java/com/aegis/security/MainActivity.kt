package com.aegis.security

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import com.aegis.security.honeytoken.HoneyTokenManager
import com.aegis.security.ui.home.aegisDataStore
import com.aegis.security.ui.navigation.AegisNavGraph
import com.aegis.security.ui.onboarding.PermissionOnboardingScreen
import com.aegis.security.ui.splash.AegisSplashScreen
import com.aegis.security.ui.theme.AegisTheme
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

private val ONBOARDING_DONE = booleanPreferencesKey("onboarding_done")

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject lateinit var honeyTokenManager: HoneyTokenManager

    override fun onCreate(savedInstanceState: Bundle?) {
        // Use the system splash only as a 1-frame bridge — our real splash is the Compose one below.
        installSplashScreen()
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Honey-token monitoring starts immediately and keeps running in the background
        // regardless of which screen (splash / onboarding / dashboard) is showing.
        honeyTokenManager.initialize()

        setContent {
            AegisTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = androidx.compose.material3.MaterialTheme.colorScheme.background
                ) {
                    AppFlow()
                }
            }
        }
    }
}

private enum class AppScreen { SPLASH, ONBOARDING, MAIN }

@Composable
private fun AppFlow() {
    val context = androidx.compose.ui.platform.LocalContext.current
    var screen by remember { mutableStateOf(AppScreen.SPLASH) }
    var onboardingNeeded by remember { mutableStateOf(true) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        val done = context.aegisDataStore.data.first()[ONBOARDING_DONE] ?: false
        onboardingNeeded = !done
    }

    when (screen) {
        AppScreen.SPLASH -> AegisSplashScreen(
            onFinished = {
                screen = if (onboardingNeeded) AppScreen.ONBOARDING else AppScreen.MAIN
            }
        )
        AppScreen.ONBOARDING -> PermissionOnboardingScreen(
            onFinished = {
                scope.launch {
                    context.aegisDataStore.edit { it[ONBOARDING_DONE] = true }
                    screen = AppScreen.MAIN
                }
            }
        )
        AppScreen.MAIN -> AegisNavGraph()
    }
}
