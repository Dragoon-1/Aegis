package com.aegis.security.ui.permissions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.domain.model.AppPermissionInfo
import com.aegis.security.permission.PermissionAuditor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class PermissionViewModel @Inject constructor(
    private val auditor: PermissionAuditor
) : ViewModel() {

    private val _apps     = MutableStateFlow<List<AppPermissionInfo>>(emptyList())
    val apps: StateFlow<List<AppPermissionInfo>> = _apps.asStateFlow()

    private val _scanning = MutableStateFlow(false)
    val scanning: StateFlow<Boolean> = _scanning.asStateFlow()

    init { scan() }

    fun scan() = viewModelScope.launch(Dispatchers.Default) {
        _scanning.value = true
        _apps.value     = auditor.auditAllApps()
        _scanning.value = false
    }
}
