package com.aegis.security.ui.assistant

import android.Manifest
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.security.domain.model.ChatMessage
import com.aegis.security.domain.model.MessageRole
import com.aegis.security.ui.theme.*
import kotlinx.coroutines.launch

val LANGUAGES = mapOf(
    "en" to "English",  "hi" to "Hindi",    "mr" to "Marathi",
    "ta" to "Tamil",    "te" to "Telugu",   "kn" to "Kannada",
    "bn" to "Bengali",  "gu" to "Gujarati", "pa" to "Punjabi",
    "fr" to "French",   "de" to "German",   "es" to "Spanish",
    "zh" to "Chinese",  "ja" to "Japanese", "ar" to "Arabic"
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AssistantScreen(
    padding:   PaddingValues,
    viewModel: AssistantViewModel = hiltViewModel()
) {
    val messages     by viewModel.messages.collectAsState()
    val isLoading    by viewModel.isLoading.collectAsState()
    val isSpeaking   by viewModel.isSpeaking.collectAsState()
    val autoSpeak    by viewModel.autoSpeak.collectAsState()
    val langCode     by viewModel.selectedLanguage.collectAsState()
    val assistantName by viewModel.assistantName.collectAsState()

    var input         by remember { mutableStateOf("") }
    var showLangMenu  by remember { mutableStateOf(false) }
    val listState     = rememberLazyListState()
    val scope         = rememberCoroutineScope()
    val context       = LocalContext.current

    // ── Runtime permission for mic ────────────────────────────────────────────
    var hasMicPermission by remember { mutableStateOf(false) }
    var pendingSpeechLaunch by remember { mutableStateOf(false) }

    val micPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasMicPermission = granted
        if (granted) pendingSpeechLaunch = true
    }

    // Check current permission state on composition
    LaunchedEffect(Unit) {
        hasMicPermission = context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    // ── Speech-to-text launcher ──────────────────────────────────────────────
    val speechLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val text = result.data
            ?.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS)
            ?.firstOrNull()
        if (!text.isNullOrBlank()) {
            viewModel.send(text)
        }
    }

    // Launch speech recognizer after permission is granted
    LaunchedEffect(pendingSpeechLaunch) {
        if (pendingSpeechLaunch && hasMicPermission) {
            pendingSpeechLaunch = false
            if (SpeechRecognizer.isRecognitionAvailable(context)) {
                speechLauncher.launch(
                    viewModel.voiceHelper.buildSpeechRecognizerIntent(langCode)
                )
            }
        }
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.lastIndex)
    }

    // ── Layout ────────────────────────────────────────────────────────────────
    // IMPORTANT: Do NOT use a nested Scaffold here. The outer Scaffold in
    // AegisNavGraph already provides a NavigationBar. A nested Scaffold's
    // bottomBar renders at the absolute screen bottom, hidden behind
    // the outer NavigationBar — that's why the mic + text field was invisible.
    // Instead, use a simple Column that accounts for the outer padding.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(AegisBgDeep)
            .padding(top = padding.calculateTopPadding())
    ) {
        // ── Top App Bar ──────────────────────────────────────────────────
        TopAppBar(
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    AssistantAvatar(isSpeaking = isSpeaking)
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text(
                            assistantName,
                            style = MaterialTheme.typography.titleMedium,
                            color = AegisOnBg
                        )
                        Text(
                            "Your security companion",
                            style = MaterialTheme.typography.labelSmall,
                            color = AegisSubtext
                        )
                    }
                }
            },
            actions = {
                IconButton(onClick = { viewModel.toggleAutoSpeak() }) {
                    Icon(
                        if (autoSpeak) Icons.Default.VolumeUp else Icons.Default.VolumeOff,
                        contentDescription = "Toggle voice replies",
                        tint = if (autoSpeak) AegisTealLight else AegisSubtext
                    )
                }
                IconButton(onClick = { viewModel.clearChat() }) {
                    Icon(Icons.Default.Delete, "Clear chat", tint = AegisSubtext)
                }
                Box {
                    TextButton(onClick = { showLangMenu = true }) {
                        Text(
                            LANGUAGES[langCode] ?: langCode, color = AegisPurpleLight,
                            style = MaterialTheme.typography.labelLarge
                        )
                        Icon(Icons.Default.ArrowDropDown, null, tint = AegisPurpleLight)
                    }
                    DropdownMenu(
                        expanded = showLangMenu,
                        onDismissRequest = { showLangMenu = false },
                        modifier = Modifier.background(AegisSurfaceVar)
                    ) {
                        LANGUAGES.forEach { (code, name) ->
                            DropdownMenuItem(
                                text = { Text(name, color = AegisOnBg) },
                                onClick = {
                                    viewModel.setLanguage(code); showLangMenu = false
                                }
                            )
                        }
                    }
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = AegisBgDeep)
        )

        // ── Chat messages ────────────────────────────────────────────────
        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 8.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(messages, key = { it.id }) { msg ->
                MessageBubble(
                    msg = msg,
                    onSpeak = { viewModel.speakLastReply() },
                    isSpeaking = isSpeaking
                )
            }
            if (isLoading) {
                item {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(start = 8.dp)
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            color = AegisPurpleLight,
                            strokeWidth = 2.dp
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "$assistantName is thinking…",
                            color = AegisSubtext,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }

        // ── Input bar (mic + text field + send) ──────────────────────────
        // This sits between the chat and the outer NavigationBar.
        // The outer NavigationBar's space is handled by
        // padding(bottom = padding.calculateBottomPadding()) on the
        // outermost Column, but since the outer Scaffold already clips
        // content, we just need to render above the nav bar.
        Surface(
            color = AegisSurface,
            tonalElevation = 4.dp,
            modifier = Modifier.padding(bottom = padding.calculateBottomPadding())
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .imePadding()
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // ── Mic button ───────────────────────────────────────────
                IconButton(
                    onClick = {
                        if (!SpeechRecognizer.isRecognitionAvailable(context)) return@IconButton
                        if (hasMicPermission) {
                            speechLauncher.launch(
                                viewModel.voiceHelper.buildSpeechRecognizerIntent(langCode)
                            )
                        } else {
                            micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                        }
                    },
                    modifier = Modifier
                        .size(44.dp)
                        .background(AegisPurpleDark, RoundedCornerShape(50))
                ) {
                    Icon(
                        Icons.Default.Mic,
                        "Speak",
                        tint = AegisPurpleLight,
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(Modifier.width(8.dp))

                // ── Text field ───────────────────────────────────────────
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    placeholder = {
                        Text("Ask $assistantName anything…", color = AegisSubtext)
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(24.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AegisPurple,
                        unfocusedBorderColor = AegisOutline,
                        focusedTextColor = AegisOnBg,
                        unfocusedTextColor = AegisOnBg,
                        cursorColor = AegisPurpleLight
                    ),
                    singleLine = false,
                    maxLines = 4,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(onSend = {
                        if (input.isNotBlank()) {
                            viewModel.send(input.trim()); input = ""
                            scope.launch {
                                if (messages.isNotEmpty())
                                    listState.animateScrollToItem(messages.lastIndex)
                            }
                        }
                    })
                )

                Spacer(Modifier.width(8.dp))

                // ── Send button ──────────────────────────────────────────
                IconButton(
                    onClick = {
                        if (input.isNotBlank()) {
                            viewModel.send(input.trim()); input = ""
                            scope.launch {
                                if (messages.isNotEmpty())
                                    listState.animateScrollToItem(messages.lastIndex)
                            }
                        }
                    },
                    enabled = input.isNotBlank() && !isLoading,
                    modifier = Modifier
                        .size(44.dp)
                        .background(
                            if (input.isNotBlank()) AegisPurple else AegisOutline,
                            RoundedCornerShape(50)
                        )
                ) {
                    Icon(
                        Icons.Default.Send, "Send",
                        tint = Color.White,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
    }
}

/** Small pulsing avatar — pulses while the assistant is speaking aloud. */
@Composable
private fun AssistantAvatar(isSpeaking: Boolean) {
    val pulse by rememberInfiniteTransition(label = "speak-pulse").animateFloat(
        initialValue = 1f,
        targetValue  = if (isSpeaking) 1.25f else 1f,
        animationSpec = infiniteRepeatable(tween(450, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "scale"
    )
    Box(
        modifier = Modifier
            .size(34.dp)
            .background(AegisPurpleDark, RoundedCornerShape(50)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            Icons.Default.SmartToy, null,
            tint = if (isSpeaking) AegisTealLight else AegisPurpleLight,
            modifier = Modifier
                .size(18.dp)
                .graphicsLayerScale(pulse)
        )
    }
}

@Composable
private fun Modifier.graphicsLayerScale(scale: Float) = this.then(
    Modifier.scale(scale)
)

@Composable
private fun MessageBubble(msg: ChatMessage, onSpeak: () -> Unit, isSpeaking: Boolean) {
    val isUser = msg.role == MessageRole.USER
    Row(
        modifier              = Modifier.fillMaxWidth(),
        horizontalArrangement = if (isUser) Arrangement.End else Arrangement.Start
    ) {
        if (!isUser) {
            Box(
                modifier         = Modifier
                    .size(32.dp)
                    .background(AegisPurpleDark, RoundedCornerShape(50)),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Default.SmartToy, null, tint = AegisPurpleLight, modifier = Modifier.size(18.dp))
            }
            Spacer(Modifier.width(8.dp))
        }
        Column {
            Surface(
                color    = if (isUser) AegisPurple else AegisSurfaceVar,
                shape    = RoundedCornerShape(
                    topStart    = if (isUser) 18.dp else 4.dp,
                    topEnd      = if (isUser) 4.dp  else 18.dp,
                    bottomStart = 18.dp, bottomEnd = 18.dp
                ),
                modifier = Modifier.widthIn(max = 290.dp)
            ) {
                Text(
                    msg.content,
                    style    = MaterialTheme.typography.bodyMedium,
                    color    = if (isUser) Color.White else AegisOnBg,
                    modifier = Modifier.padding(12.dp)
                )
            }
            if (!isUser) {
                TextButton(onClick = onSpeak, modifier = Modifier.height(26.dp)) {
                    Icon(
                        if (isSpeaking) Icons.Default.VolumeUp else Icons.Default.PlayArrow,
                        null, tint = AegisSubtext, modifier = Modifier.size(14.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text("Listen", style = MaterialTheme.typography.labelSmall, color = AegisSubtext)
                }
            }
        }
        if (isUser) {
            Spacer(Modifier.width(8.dp))
            Box(
                modifier         = Modifier
                    .size(32.dp)
                    .background(AegisTeal, RoundedCornerShape(50)),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Default.Person, null, tint = Color.White, modifier = Modifier.size(18.dp))
            }
        }
    }
}
