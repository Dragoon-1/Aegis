package com.aegis.security.ui.assistant

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.data.remote.AegisApiService
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.AssistantRequest
import com.aegis.security.domain.model.ChatMessage
import com.aegis.security.domain.model.MessageRole
import com.aegis.security.domain.model.ThreatEvent
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * AssistantViewModel
 *
 * Powers the AI Guard chat screen. Two ways messages appear:
 *  1. User types/speaks a question  -> sent to backend Gemini endpoint
 *  2. A new HIGH/CRITICAL threat is detected anywhere in the app
 *     -> assistant proactively posts a "here's what to do" message,
 *        without the user needing to ask first.
 */
@HiltViewModel
class AssistantViewModel @Inject constructor(
    private val api: AegisApiService,
    private val threatRepository: ThreatRepository,
    val voiceHelper: VoiceHelper
) : ViewModel() {

    private val _selectedLanguage = MutableStateFlow("en")
    val selectedLanguage: StateFlow<String> = _selectedLanguage.asStateFlow()

    private val _messages = MutableStateFlow<List<ChatMessage>>(
        listOf(greetingMessage("en"))
    )
    val messages: StateFlow<List<ChatMessage>> = _messages.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    /** True while the assistant's reply is being read aloud. */
    private val _isSpeaking = MutableStateFlow(false)
    val isSpeaking: StateFlow<Boolean> = _isSpeaking.asStateFlow()

    /** Voice auto-read toggle — when on, every assistant reply is spoken aloud automatically. */
    private val _autoSpeak = MutableStateFlow(false)
    val autoSpeak: StateFlow<Boolean> = _autoSpeak.asStateFlow()

    val assistantName: StateFlow<String> = selectedLanguage
        .map { AssistantPersona.nameFor(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), AssistantPersona.nameFor("en"))

    init {
        observeNewThreatsForProactiveAssist()
    }

    // ── Language ──────────────────────────────────────────────────────────────

    fun setLanguage(lang: String) {
        _selectedLanguage.value = lang
    }

    // ── Sending a message ────────────────────────────────────────────────────

    fun send(question: String) {
        if (question.isBlank() || _isLoading.value) return

        _messages.value = _messages.value + ChatMessage(
            role = MessageRole.USER,
            content = question.trim()
        )
        _isLoading.value = true

        viewModelScope.launch {
            try {
                val response = api.askAssistant(
                    AssistantRequest(question = question.trim(), language = _selectedLanguage.value)
                )
                postAssistantReply(response.answer)
            } catch (e: Exception) {
                postAssistantReply(fallbackErrorMessage(_selectedLanguage.value))
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun toggleAutoSpeak() {
        _autoSpeak.value = !_autoSpeak.value
        if (!_autoSpeak.value) {
            voiceHelper.stopSpeaking()
            _isSpeaking.value = false
        }
    }

    fun speakLastReply() {
        val last = _messages.value.lastOrNull { it.role == MessageRole.ASSISTANT } ?: return
        speak(last.content)
    }

    fun stopSpeaking() {
        voiceHelper.stopSpeaking()
        _isSpeaking.value = false
    }

    fun clearChat() {
        _messages.value = listOf(greetingMessage(_selectedLanguage.value))
    }

    // ── Proactive assistance ─────────────────────────────────────────────────

    /**
     * Watches the threat repository. Any time a NEW high-severity threat is
     * saved (anywhere in the app — honey-token, VPN, SMS, overlay, permission
     * auditor), the assistant pushes an unsolicited "here's what to do" message
     * into the chat, as if it noticed and stepped in on its own.
     */
    private fun observeNewThreatsForProactiveAssist() {
        threatRepository.getAllThreats()
            .map { list -> list.firstOrNull() }   // most recent threat
            .distinctUntilChanged { old, new -> old?.id == new?.id }
            .drop(1) // skip the initial emission so we don't greet on app launch with old data
            .onEach { latest -> latest?.let { onNewThreatDetected(it) } }
            .launchIn(viewModelScope)
    }

    private fun onNewThreatDetected(threat: ThreatEvent) {
        val isWorthInterrupting = threat.severity.level >= 3 // HIGH, CRITICAL, EMERGENCY
        if (!isWorthInterrupting) return

        val lang = _selectedLanguage.value
        val proactiveText = AssistantPersona.proactiveAlertFor(lang, threat.title, threat.description)

        _messages.value = _messages.value + ChatMessage(
            role = MessageRole.ASSISTANT,
            content = proactiveText
        )

        if (_autoSpeak.value) speak(proactiveText)

        // Ask the backend for tailored next-step guidance using this threat as context
        viewModelScope.launch {
            try {
                val response = api.askAssistant(
                    AssistantRequest(
                        question = "A threat was just detected on this device: ${threat.title} — ${threat.description}. " +
                                "In 3 short steps, tell the user exactly what to do right now.",
                        language = lang,
                        threat_context = mapOf(
                            "type" to threat.type.name,
                            "severity" to threat.severity.label
                        )
                    )
                )
                postAssistantReply(response.answer)
            } catch (e: Exception) {
                // Silent — the proactive alert message above already gives the user something
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun postAssistantReply(text: String) {
        _messages.value = _messages.value + ChatMessage(role = MessageRole.ASSISTANT, content = text)
        if (_autoSpeak.value) speak(text)
    }

    private fun speak(text: String) {
        _isSpeaking.value = true
        voiceHelper.speak(text, _selectedLanguage.value)
        // TTS completion callback wiring can refine this; for now clear after a delay proportional to length
        viewModelScope.launch {
            kotlinx.coroutines.delay((text.length * 55L).coerceIn(800L, 12_000L))
            _isSpeaking.value = false
        }
    }

    override fun onCleared() {
        super.onCleared()
        voiceHelper.shutdown()
    }

    companion object {
        private fun greetingMessage(lang: String) = ChatMessage(
            id = UUID.randomUUID().toString(),
            role = MessageRole.ASSISTANT,
            content = AssistantPersona.greetingFor(lang)
        )

        private fun fallbackErrorMessage(lang: String): String = when (lang) {
            "hi", "mr" -> "मुझे जोड़ने में समस्या हो रही है। कृपया अपना इंटरनेट जांचें और फिर कोशिश करें।"
            "fr" -> "J'ai du mal à me connecter. Vérifiez votre connexion et réessayez."
            "es" -> "Tengo problemas para conectarme. Revisa tu conexión e intenta de nuevo."
            else -> "I'm having trouble connecting right now. Please check your internet connection and try again."
        }
    }
}
