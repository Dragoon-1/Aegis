package com.aegis.security.di

import android.content.Context
import androidx.room.Room
import com.aegis.security.data.local.AegisDatabase
import com.aegis.security.data.local.ThreatDao
import com.aegis.security.data.remote.AegisApiService
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    // ── Room Database ─────────────────────────────────────────────────────

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext ctx: Context): AegisDatabase =
        Room.databaseBuilder(ctx, AegisDatabase::class.java, "aegis_db")
            .fallbackToDestructiveMigration()
            .build()

    @Provides
    fun provideThreatDao(db: AegisDatabase): ThreatDao = db.threatDao()

    // ── Network (Retrofit + OkHttp) ───────────────────────────────────────

    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient =
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .addInterceptor(
                HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.BODY
                }
            )
            .build()

    @Provides
    @Singleton
    fun provideRetrofit(client: OkHttpClient): Retrofit =
        Retrofit.Builder()
            // Change to your deployed backend URL in production
            // TODO: Replace with your backend server IP before running
            .baseUrl("http://10.0.2.2:8000/")   // 10.0.2.2 = localhost via Android emulator
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build()

    @Provides
    @Singleton
    fun provideApiService(retrofit: Retrofit): AegisApiService =
        retrofit.create(AegisApiService::class.java)
}
