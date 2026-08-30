package com.shieldscan.app.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.navigation.NavType
import com.shieldscan.app.ui.MainViewModel
import com.shieldscan.app.ui.history.HistoryDetailScreen
import com.shieldscan.app.ui.history.HistoryScreen
import com.shieldscan.app.ui.home.HomeScreen
import com.shieldscan.app.ui.results.ScanResultsScreen
import com.shieldscan.app.ui.settings.SettingsScreen

private object Routes {
    const val HOME = "home"
    const val RESULTS = "results"
    const val HISTORY = "history"
    const val HISTORY_DETAIL = "history_detail/{scanId}"
    const val SETTINGS = "settings"

    fun historyDetail(scanId: Long) = "history_detail/$scanId"
}

private data class BottomTab(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

private val bottomTabs = listOf(
    BottomTab(Routes.HOME, "Home", Icons.Filled.Home),
    BottomTab(Routes.HISTORY, "History", Icons.Filled.History),
    BottomTab(Routes.SETTINGS, "Settings", Icons.Filled.Settings)
)

@Composable
fun ShieldScanNavHost(viewModel: MainViewModel) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route
    val showBottomBar = bottomTabs.any { it.route == currentRoute }

    Scaffold(
        bottomBar = {
            if (showBottomBar) {
                NavigationBar {
                    bottomTabs.forEach { tab ->
                        val selected = backStackEntry?.destination?.hierarchy?.any { it.route == tab.route } == true
                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                navController.navigate(tab.route) {
                                    popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = { Icon(tab.icon, contentDescription = tab.label) },
                            label = { Text(tab.label) }
                        )
                    }
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = Routes.HOME,
            modifier = androidx.compose.ui.Modifier.padding(padding)
        ) {
            composable(Routes.HOME) {
                HomeScreen(
                    viewModel = viewModel,
                    onScanCompleted = { navController.navigate(Routes.RESULTS) }
                )
            }
            composable(Routes.RESULTS) {
                ScanResultsScreen(viewModel = viewModel, onBack = { navController.popBackStack() })
            }
            composable(Routes.HISTORY) {
                HistoryScreen(
                    viewModel = viewModel,
                    onOpenScan = { scanId -> navController.navigate(Routes.historyDetail(scanId)) }
                )
            }
            composable(
                route = Routes.HISTORY_DETAIL,
                arguments = listOf(navArgument("scanId") { type = NavType.LongType })
            ) { entry ->
                val scanId = entry.arguments?.getLong("scanId") ?: 0L
                HistoryDetailScreen(viewModel = viewModel, scanId = scanId, onBack = { navController.popBackStack() })
            }
            composable(Routes.SETTINGS) {
                SettingsScreen(viewModel = viewModel)
            }
        }
    }
}
