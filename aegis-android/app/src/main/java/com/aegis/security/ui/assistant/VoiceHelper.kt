package com.aegis.security.ui.assistant

import android.content.Context
import android.content.Intent
import android.speech.RecognizerIntent
import android.speech.tts.TextToSpeech
import android.util.Log
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton
import dagger.hilt.android.qualifiers.ApplicationContext

/**
 * AEGIS VOICE HELPER
 *
 * Powers the mic (speech-to-text) and speaker (text-to-speech) buttons
 * on the AI Assistant screen. Supports the same language list as the
 * assistant's text responses.
 */
@Singleton
class VoiceHelper @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private var tts: TextToSpeech? = null
    private var isTtsReady = false

    companion object {
        private const val TAG = "AegisVoice"

        private val LOCALE_MAP = mapOf(
            "en" to Locale("en", "IN"),
            "hi" to Locale("hi", "IN"),
            "mr" to Locale("mr", "IN"),
            "ta" to Locale("ta", "IN"),
            "te" to Locale("te", "IN"),
            "kn" to Locale("kn", "IN"),
            "bn" to Locale("bn", "IN"),
            "gu" to Locale("gu", "IN"),
            "pa" to Locale("pa", "IN"),
            "fr" to Locale.FRENCH,
            "de" to Locale.GERMAN,
            "es" to Locale("es", "ES"),
            "zh" to Locale.SIMPLIFIED_CHINESE,
            "ja" to Locale.JAPANESE,
            "ar" to Locale("ar", "SA"),
        )
    }

    fun localeFor(languageCode: String): Locale = LOCALE_MAP[languageCode] ?: Locale.US

    /** Builds the intent for Android's built-in speech recognizer. Launch via registerForActivityResult. */
    fun buildSpeechRecognizerIntent(languageCode: String): Intent {
        return Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, localeFor(languageCode).toLanguageTag())
            putExtra(RecognizerIntent.EXTRA_PROMPT, "Speak now…")
        }
    }

    /** Initializes TTS once. Safe to call multiple times. */
    private fun ensureTts(languageCode: String, onReady: () -> Unit) {
        if (tts != null && isTtsReady) {
            tts?.language = localeFor(languageCode)
            onReady()
            return
        }
        tts = TextToSpeech(context) { status ->
            if (status == TextToSpeech.SUCCESS) {
                isTtsReady = true
                tts?.language = localeFor(languageCode)
                onReady()
            } else {
                Log.w(TAG, "TTS init failed: $status")
            }
        }
    }

    fun speak(text: String, languageCode: String) {
        ensureTts(languageCode) {
            tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, "aegis_utterance")
        }
    }

    fun stopSpeaking() {
        tts?.stop()
    }

    fun shutdown() {
        tts?.stop()
        tts?.shutdown()
        tts = null
        isTtsReady = false
    }
}
