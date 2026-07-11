# ── Aegis ProGuard Rules ─────────────────────────────────────────────────────

# Keep Hilt entry points
-keep class dagger.hilt.** { *; }
-keep @dagger.hilt.android.HiltAndroidApp class * { *; }
-keep @dagger.hilt.android.AndroidEntryPoint class * { *; }

# Keep Room entities and DAOs
-keep class com.aegis.security.data.local.** { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao    class * { *; }

# Keep domain models (used by Gson for API serialisation)
-keep class com.aegis.security.domain.model.** { *; }

# Keep Retrofit API interfaces
-keep interface com.aegis.security.data.remote.** { *; }
-keep class retrofit2.** { *; }
-keepattributes Signature, Exceptions, *Annotation*

# Keep Gson serialisation
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**

# Keep OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**

# Keep Compose
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# Keep Coroutines
-keep class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**

# Keep WorkManager workers
-keep class * extends androidx.work.Worker
-keep class * extends androidx.work.CoroutineWorker

# Keep BroadcastReceivers and Services (declared in manifest)
-keep class com.aegis.security.sms.SmsReceiver      { *; }
-keep class com.aegis.security.BootReceiver          { *; }
-keep class com.aegis.security.vpn.AegisVpnService   { *; }

# Suppress warnings for optional dependencies
-dontwarn org.web3j.**
-dontwarn org.bouncycastle.**
