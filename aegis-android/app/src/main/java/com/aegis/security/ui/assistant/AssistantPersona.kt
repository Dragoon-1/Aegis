package com.aegis.security.ui.assistant

/**
 * AEGIS ASSISTANT PERSONA
 *
 * The assistant's display name changes based on the user's selected language,
 * giving it a local, friendly identity rather than a generic "AI Assistant" feel.
 */
object AssistantPersona {

    private val NAMES = mapOf(
        "en" to "Mate",
        "hi" to "सखा",      // Sakha
        "mr" to "सखा",      // Sakha (Marathi)
        "ta" to "தோழன்",    // Thozhan (companion)
        "te" to "మిత్రుడు",  // Mitrudu (friend)
        "kn" to "ಗೆಳೆಯ",     // Geleya (friend)
        "bn" to "সাথী",      // Sathi (companion)
        "gu" to "મિત્ર",      // Mitra (friend)
        "pa" to "ਮਿੱਤਰ",     // Mittar (friend)
        "fr" to "Copain",
        "de" to "Kumpel",
        "es" to "Compa",
        "zh" to "伙伴",       // Huoban (partner)
        "ja" to "相棒",       // Aibou (partner)
        "ar" to "صاحبي"      // Sahbi (my friend)
    )

    fun nameFor(languageCode: String): String =
        NAMES[languageCode] ?: NAMES["en"]!!

    fun greetingFor(languageCode: String): String {
        val name = nameFor(languageCode)
        return when (languageCode) {
            "hi", "mr" -> "नमस्ते! मैं $name हूं, आपका सुरक्षा साथी। मैं आपके फोन पर किसी भी खतरे में आपकी मदद करूंगा।"
            "ta" -> "வணக்கம்! நான் $name, உங்கள் பாதுகாப்பு துணை."
            "te" -> "నమస్కారం! నేను $name, మీ భద్రతా మిత్రుడు."
            "fr" -> "Bonjour ! Je suis $name, votre compagnon de sécurité."
            "de" -> "Hallo! Ich bin $name, dein Sicherheitsbegleiter."
            "es" -> "¡Hola! Soy $name, tu compañero de seguridad."
            else -> "Hi! I'm $name, your security companion. I'll watch over your phone and help you handle any threats that come up — just ask me anything."
        }
    }

    /** Message shown when the assistant proactively reaches out after a threat is detected. */
    fun proactiveAlertFor(languageCode: String, threatTitle: String, threatDescription: String): String {
        val name = nameFor(languageCode)
        return when (languageCode) {
            "hi", "mr" -> "$name यहाँ! मुझे एक खतरा मिला: \"$threatTitle\"। $threatDescription मैं आपको बताता हूं कि क्या करना है।"
            "fr" -> "$name ici ! J'ai détecté une menace : \"$threatTitle\". $threatDescription Laissez-moi vous guider."
            "es" -> "¡$name aquí! Detecté una amenaza: \"$threatTitle\". $threatDescription Te diré qué hacer."
            else -> "$name here! I just caught something: \"$threatTitle\". $threatDescription Let me walk you through what to do next."
        }
    }
}
