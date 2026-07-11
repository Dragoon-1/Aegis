package com.aegis.security.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SmartToy
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.aegis.security.ui.assistant.AssistantScreen
import com.aegis.security.ui.home.HomeScreen
import com.aegis.security.ui.permissions.PermissionAuditScreen
import com.aegis.security.ui.settings.SettingsScreen
import com.aegis.security.ui.threats.ThreatListScreen

sealed class Screen(val route: String, val label: String, val icon: ImageVector) {
    object Home       : Screen("home",       "Dashboard",  Icons.Default.Home)
    object Threats    : Screen("threats",    "Threats",    Icons.Default.Security)
    object Assistant  : Screen("assistant",  "AI Guard",   Icons.Default.SmartToy)
    object Settings   : Screen("settings",  "Settings",   Icons.Default.Settings)
}

private val bottomNavItems = listOf(
    Screen.Home, Screen.Threats, Screen.Assistant, Screen.Settings
)

@Composable
fun AegisNavGraph() {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDest = navBackStackEntry?.destination

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = androidx.compose.ui.graphics.Color(0xFF12122A),
                contentColor   = MaterialTheme.colorScheme.onSurface
            ) {
                bottomNavItems.forEach { screen ->
                    val selected = currentDest?.hierarchy
                        ?.any { it.route == screen.route } == true

                    NavigationBarItem(
                        selected = selected,
                        onClick  = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState    = true
                            }
                        },
                        icon     = { Icon(screen.icon, contentDescription = screen.label) },
                        label    = { Text(screen.label, style = MaterialTheme.typography.labelSmall) },
                        colors   = NavigationBarItemDefaults.colors(
                            selectedIconColor   = MaterialTheme.colorScheme.primary,
                            selectedTextColor   = MaterialTheme.colorScheme.primary,
                            unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            indicatorColor      = MaterialTheme.colorScheme.primaryContainer
                        )
                    )
                }
            }
        }
    ) { padding ->
        NavHost(
            navController    = navController,
            startDestination = Screen.Home.route
        ) {
            composable(Screen.Home.route)      { HomeScreen(padding, navController) }
            composable(Screen.Threats.route)   { ThreatListScreen(padding) }
            composable(Screen.Assistant.route) { AssistantScreen(padding) }
            composable(Screen.Settings.route)  { SettingsScreen(padding) }
            composable("permissions")          { PermissionAuditScreen(padding) }
        }
    }
}
