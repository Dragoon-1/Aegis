package com.aegis.security.data.local

import androidx.room.*
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.domain.model.ThreatType
import kotlinx.coroutines.flow.Flow

// ── Type converters so Room can store our enums ───────────────────────────────

class AegisTypeConverters {
    @TypeConverter fun fromThreatType(v: ThreatType): String = v.name
    @TypeConverter fun toThreatType(v: String): ThreatType = ThreatType.valueOf(v)
    @TypeConverter fun fromSeverity(v: Severity): String = v.name
    @TypeConverter fun toSeverity(v: String): Severity = Severity.valueOf(v)
}

// ── DAO ───────────────────────────────────────────────────────────────────────

@Dao
interface ThreatDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(threat: ThreatEvent)

    @Query("SELECT * FROM threats ORDER BY timestamp DESC")
    fun getAllThreats(): Flow<List<ThreatEvent>>

    @Query("SELECT * FROM threats WHERE isResolved = 0 ORDER BY timestamp DESC")
    fun getActiveThreats(): Flow<List<ThreatEvent>>

    @Query("SELECT * FROM threats ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentThreats(limit: Int = 50): List<ThreatEvent>

    @Query("SELECT COUNT(*) FROM threats")
    fun getThreatCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM threats WHERE timestamp > :since")
    suspend fun getCountSince(since: Long): Int

    @Query("UPDATE threats SET isResolved = 1 WHERE id = :id")
    suspend fun resolve(id: String)

    @Query("UPDATE threats SET reportedToBackend = 1 WHERE id = :id")
    suspend fun markReportedToBackend(id: String)

    @Query("UPDATE threats SET reportedToBlockchain = 1 WHERE id = :id")
    suspend fun markReportedToBlockchain(id: String)

    @Query("SELECT * FROM threats WHERE reportedToBackend = 0")
    suspend fun getUnreportedThreats(): List<ThreatEvent>

    @Query("DELETE FROM threats WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)
}

// ── Database ──────────────────────────────────────────────────────────────────

@Database(
    entities = [ThreatEvent::class],
    version  = 1,
    exportSchema = false
)
@TypeConverters(AegisTypeConverters::class)
abstract class AegisDatabase : RoomDatabase() {
    abstract fun threatDao(): ThreatDao
}
