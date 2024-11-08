package com.koalasat.pokey.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface ApplicationDao {
    @Query("SELECT MAX(time) FROM notification")
    fun getLatestNotification(): Long?

    @Query("SELECT EXISTS (SELECT 1 FROM notification WHERE eventId = :eventId)")
    fun existsNotification(eventId: String): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertNotification(notificationEntity: NotificationEntity): Long?

    @Query("SELECT EXISTS (SELECT 1 FROM relay WHERE url = :url AND kind = :kind)")
    fun existsRelay(url: String, kind: Int): Int

    @Query("SELECT * FROM relay WHERE read = 1")
    fun getReadRelays(): List<RelayEntity>

    @Query("SELECT * FROM relay where kind = :kind")
    fun getRelaysByKind(kind: Int): List<RelayEntity>

    @Query("SELECT MAX(createdAt) FROM relay WHERE kind = :kind")
    fun getLatestRelaysByKind(kind: Int): Long?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertRelay(notificationEntity: RelayEntity): Long?

    @Query("DELETE FROM relay where kind = :kind")
    fun deleteRelaysByKind(kind: Int): Int

    @Query("DELETE FROM relay where url = :url and kind = :kind")
    fun deleteRelayByUrl(url: String, kind: Int): Int
}
