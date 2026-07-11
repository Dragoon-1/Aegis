package com.aegis.security.ui.threats

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ThreatViewModel @Inject constructor(
    private val repository: ThreatRepository
) : ViewModel() {

    private val _filter = MutableStateFlow<Severity?>(null)
    val filter: StateFlow<Severity?> = _filter.asStateFlow()

    val threats: StateFlow<List<ThreatEvent>> = repository.getAllThreats()
        .combine(_filter) { list, severity ->
            if (severity == null) list
            else list.filter { it.severity == severity }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun setFilter(severity: Severity?) {
        _filter.value = severity
    }

    fun resolve(id: String) = viewModelScope.launch {
        repository.resolve(id)
    }
}
