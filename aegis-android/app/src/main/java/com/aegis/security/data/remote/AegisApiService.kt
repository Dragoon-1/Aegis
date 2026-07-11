package com.aegis.security.data.remote

import com.aegis.security.domain.model.AssistantRequest
import com.aegis.security.domain.model.AssistantResponse
import com.aegis.security.domain.model.ThreatCheckResult
import com.aegis.security.domain.model.ThreatReportRequest
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

interface AegisApiService {

    @POST("v1/threats/report")
    suspend fun reportThreat(@Body request: ThreatReportRequest): Map<String, Any>

    @POST("v1/threats/batch-check")
    suspend fun batchCheckThreats(
        @Body body: Map<String, List<String>>
    ): Map<String, ThreatCheckResult>

    @GET("v1/threats/recent")
    suspend fun getRecentThreats(
        @Query("limit") limit: Int = 500,
        @Query("threat_type") type: String? = null
    ): List<Map<String, Any>>

    @GET("v1/dashboard/stats")
    suspend fun getDashboardStats(): Map<String, Any>

    @POST("v1/assistant/ask")
    suspend fun askAssistant(@Body request: AssistantRequest): AssistantResponse

    @POST("v1/reports/generate-now")
    suspend fun generatePoliceReport(): Map<String, String>
}
